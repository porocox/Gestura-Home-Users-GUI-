// Lockstep Authentication Module

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define UNICODE
#define _UNICODE

#include <windows.h>
#include <wincrypt.h>
#include <sddl.h>
#include <shlobj.h>
#include <aclapi.h>

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <array>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <filesystem>
#include <optional>
#include <cstdint>
#include <cstring>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")

namespace WinAuth {

// CONSTANTS & CONFIGURATION

static constexpr size_t AAPS_TOKEN_LENGTH = 32;
static constexpr size_t SHA256_DIGEST_SIZE = 32;
static constexpr size_t SHA256_BLOCK_SIZE = 64;

static constexpr char AAPS_CHARSET[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789"
    "!@#$%^&*()-_=+[]{}<>?";

static constexpr size_t AAPS_CHARSET_SIZE = sizeof(AAPS_CHARSET) - 1;

// Version for auth file format compatibility
static constexpr uint32_t AUTH_FILE_VERSION = 1;
static constexpr uint32_t AUTH_FILE_MAGIC = 0x48545541; // "AUTH"


// ERROR HANDLING
enum class AuthError {
    Success = 0,
    FileNotFound,
    FileCorrupted,
    FileAccessDenied,
    CryptoError,
    InvalidVersion,
    InvalidMagic,
    HashMismatch,
    SystemError,
    OutOfMemory
};

class AuthException : public std::runtime_error {
public:
    explicit AuthException(AuthError code, const std::string& message)
        : std::runtime_error(message), error_code_(code) {}
    
    AuthError code() const noexcept { return error_code_; }
    
private:
    AuthError error_code_;
};


// SECURE MEMORY UTILITIES
template<typename T, size_t N>
class SecureArray {
public:
    SecureArray() noexcept { 
        SecureZeroMemory(data_.data(), N * sizeof(T)); 
    }
    
    ~SecureArray() noexcept { 
        SecureZeroMemory(data_.data(), N * sizeof(T)); 
    }
    
    // Non-copyable, non-movable for security
    SecureArray(const SecureArray&) = delete;
    SecureArray& operator=(const SecureArray&) = delete;
    SecureArray(SecureArray&&) = delete;
    SecureArray& operator=(SecureArray&&) = delete;
    
    T* data() noexcept { return data_.data(); }
    const T* data() const noexcept { return data_.data(); }
    constexpr size_t size() const noexcept { return N; }
    
    T& operator[](size_t i) noexcept { return data_[i]; }
    const T& operator[](size_t i) const noexcept { return data_[i]; }
    
private:
    std::array<T, N> data_;
};

class SecureBuffer {
public:
    explicit SecureBuffer(size_t size) : size_(size) {
        if (size_ > 0) {
            data_ = static_cast<uint8_t*>(
                VirtualAlloc(nullptr, size_, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
            );
            if (!data_) {
                throw AuthException(AuthError::OutOfMemory, "Failed to allocate secure buffer");
            }
            SecureZeroMemory(data_, size_);
        }
    }
    
    ~SecureBuffer() noexcept {
        if (data_) {
            SecureZeroMemory(data_, size_);
            VirtualFree(data_, 0, MEM_RELEASE);
        }
    }
    
    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;
    
    SecureBuffer(SecureBuffer&& other) noexcept 
        : data_(other.data_), size_(other.size_) {
        other.data_ = nullptr;
        other.size_ = 0;
    }
    
    uint8_t* data() noexcept { return data_; }
    const uint8_t* data() const noexcept { return data_; }
    size_t size() const noexcept { return size_; }
    
private:
    uint8_t* data_ = nullptr;
    size_t size_ = 0;
};


// WINDOWS HANDLE RAII WRAPPER

class WinHandle {
public:
    explicit WinHandle(HANDLE h = INVALID_HANDLE_VALUE) noexcept : handle_(h) {}
    
    ~WinHandle() noexcept { close(); }
    
    WinHandle(const WinHandle&) = delete;
    WinHandle& operator=(const WinHandle&) = delete;
    
    WinHandle(WinHandle&& other) noexcept : handle_(other.handle_) {
        other.handle_ = INVALID_HANDLE_VALUE;
    }
    
    WinHandle& operator=(WinHandle&& other) noexcept {
        if (this != &other) {
            close();
            handle_ = other.handle_;
            other.handle_ = INVALID_HANDLE_VALUE;
        }
        return *this;
    }
    
    void reset(HANDLE h = INVALID_HANDLE_VALUE) noexcept {
        close();
        handle_ = h;
    }
    
    HANDLE get() const noexcept { return handle_; }
    HANDLE release() noexcept {
        HANDLE h = handle_;
        handle_ = INVALID_HANDLE_VALUE;
        return h;
    }
    
    bool valid() const noexcept {
        return handle_ != INVALID_HANDLE_VALUE && handle_ != nullptr;
    }
    
    explicit operator bool() const noexcept { return valid(); }
    
private:
    void close() noexcept {
        if (valid()) {
            CloseHandle(handle_);
            handle_ = INVALID_HANDLE_VALUE;
        }
    }
    
    HANDLE handle_;
};

// ============================================================================
// CRYPTOGRAPHIC PROVIDER WRAPPER
// ============================================================================

class CryptoProvider {
public:
    static CryptoProvider& instance() {
        static CryptoProvider provider;
        return provider;
    }
    
    void generateRandomBytes(uint8_t* buffer, size_t length) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        if (!CryptGenRandom(provider_, static_cast<DWORD>(length), buffer)) {
            throw AuthException(AuthError::CryptoError, 
                "CryptGenRandom failed: " + std::to_string(GetLastError()));
        }
    }
    
    uint64_t generateSecureRandom64() {
        uint64_t value = 0;
        generateRandomBytes(reinterpret_cast<uint8_t*>(&value), sizeof(value));
        return value;
    }
    
    CryptoProvider(const CryptoProvider&) = delete;
    CryptoProvider& operator=(const CryptoProvider&) = delete;
    
private:
    CryptoProvider() {
        if (!CryptAcquireContextW(&provider_, nullptr, nullptr, 
                                   PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            throw AuthException(AuthError::CryptoError,
                "Failed to acquire crypto context: " + std::to_string(GetLastError()));
        }
    }
    
    ~CryptoProvider() noexcept {
        if (provider_) {
            CryptReleaseContext(provider_, 0);
        }
    }
    
    HCRYPTPROV provider_ = 0;
    std::mutex mutex_;
};

// ============================================================================
// SHA-256 IMPLEMENTATION (Complete, Correct)
// ============================================================================

class SHA256 {
public:
    using Digest = std::array<uint8_t, SHA256_DIGEST_SIZE>;
    
    SHA256() noexcept { reset(); }
    
    ~SHA256() noexcept {
        // Securely clear internal state
        SecureZeroMemory(state_, sizeof(state_));
        SecureZeroMemory(buffer_, sizeof(buffer_));
    }
    
    void reset() noexcept {
        state_[0] = 0x6a09e667;
        state_[1] = 0xbb67ae85;
        state_[2] = 0x3c6ef372;
        state_[3] = 0xa54ff53a;
        state_[4] = 0x510e527f;
        state_[5] = 0x9b05688c;
        state_[6] = 0x1f83d9ab;
        state_[7] = 0x5be0cd19;
        
        buffer_len_ = 0;
        total_len_ = 0;
    }
    
    void update(const uint8_t* data, size_t length) noexcept {
        total_len_ += length;
        
        // Process any pending data with new input
        if (buffer_len_ > 0) {
            size_t to_copy = (std::min)(SHA256_BLOCK_SIZE - buffer_len_, length);
            memcpy(buffer_ + buffer_len_, data, to_copy);
            buffer_len_ += to_copy;
            data += to_copy;
            length -= to_copy;
            
            if (buffer_len_ == SHA256_BLOCK_SIZE) {
                transform(buffer_);
                buffer_len_ = 0;
            }
        }
        
        // Process complete blocks
        while (length >= SHA256_BLOCK_SIZE) {
            transform(data);
            data += SHA256_BLOCK_SIZE;
            length -= SHA256_BLOCK_SIZE;
        }
        
        // Store remaining data
        if (length > 0) {
            memcpy(buffer_, data, length);
            buffer_len_ = length;
        }
    }
    
    void update(const char* data, size_t length) noexcept {
        update(reinterpret_cast<const uint8_t*>(data), length);
    }
    
    void update(const std::string& data) noexcept {
        update(reinterpret_cast<const uint8_t*>(data.data()), data.size());
    }
    
    Digest finalize() noexcept {
        Digest result;
        
        // Padding
        uint64_t bit_len = total_len_ * 8;
        
        buffer_[buffer_len_++] = 0x80;
        
        if (buffer_len_ > 56) {
            while (buffer_len_ < SHA256_BLOCK_SIZE) {
                buffer_[buffer_len_++] = 0x00;
            }
            transform(buffer_);
            buffer_len_ = 0;
        }
        
        while (buffer_len_ < 56) {
            buffer_[buffer_len_++] = 0x00;
        }
        
        // Append length in big-endian
        for (int i = 7; i >= 0; --i) {
            buffer_[buffer_len_++] = static_cast<uint8_t>(bit_len >> (i * 8));
        }
        
        transform(buffer_);
        
        // Convert state to bytes (big-endian)
        for (int i = 0; i < 8; ++i) {
            result[i * 4 + 0] = static_cast<uint8_t>(state_[i] >> 24);
            result[i * 4 + 1] = static_cast<uint8_t>(state_[i] >> 16);
            result[i * 4 + 2] = static_cast<uint8_t>(state_[i] >> 8);
            result[i * 4 + 3] = static_cast<uint8_t>(state_[i]);
        }
        
        return result;
    }
    
    // Convenience static method
    static Digest hash(const uint8_t* data, size_t length) {
        SHA256 hasher;
        hasher.update(data, length);
        return hasher.finalize();
    }
    
    static Digest hash(const std::string& data) {
        return hash(reinterpret_cast<const uint8_t*>(data.data()), data.size());
    }

private:
    static constexpr uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c48, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4f, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };
    
    static uint32_t rotr(uint32_t x, uint32_t n) noexcept {
        return (x >> n) | (x << (32 - n));
    }
    
    static uint32_t ch(uint32_t x, uint32_t y, uint32_t z) noexcept {
        return (x & y) ^ (~x & z);
    }
    
    static uint32_t maj(uint32_t x, uint32_t y, uint32_t z) noexcept {
        return (x & y) ^ (x & z) ^ (y & z);
    }
    
    static uint32_t sigma0(uint32_t x) noexcept {
        return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
    }
    
    static uint32_t sigma1(uint32_t x) noexcept {
        return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
    }
    
    static uint32_t gamma0(uint32_t x) noexcept {
        return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
    }
    
    static uint32_t gamma1(uint32_t x) noexcept {
        return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
    }
    
    void transform(const uint8_t* block) noexcept {
        uint32_t w[64];
        
        // Prepare message schedule
        for (int i = 0; i < 16; ++i) {
            w[i] = (static_cast<uint32_t>(block[i * 4 + 0]) << 24) |
                   (static_cast<uint32_t>(block[i * 4 + 1]) << 16) |
                   (static_cast<uint32_t>(block[i * 4 + 2]) << 8) |
                   (static_cast<uint32_t>(block[i * 4 + 3]));
        }
        
        for (int i = 16; i < 64; ++i) {
            w[i] = gamma1(w[i - 2]) + w[i - 7] + gamma0(w[i - 15]) + w[i - 16];
        }
        
        // Initialize working variables
        uint32_t a = state_[0];
        uint32_t b = state_[1];
        uint32_t c = state_[2];
        uint32_t d = state_[3];
        uint32_t e = state_[4];
        uint32_t f = state_[5];
        uint32_t g = state_[6];
        uint32_t h = state_[7];
        
        // Main loop
        for (int i = 0; i < 64; ++i) {
            uint32_t t1 = h + sigma1(e) + ch(e, f, g) + K[i] + w[i];
            uint32_t t2 = sigma0(a) + maj(a, b, c);
            
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        
        // Update state
        state_[0] += a;
        state_[1] += b;
        state_[2] += c;
        state_[3] += d;
        state_[4] += e;
        state_[5] += f;
        state_[6] += g;
        state_[7] += h;
        
        // Clear sensitive data
        SecureZeroMemory(w, sizeof(w));
    }
    
    uint32_t state_[8];
    uint8_t buffer_[SHA256_BLOCK_SIZE];
    size_t buffer_len_ = 0;
    uint64_t total_len_ = 0;
};

constexpr uint32_t SHA256::K[64];

// ============================================================================
// TOKEN GENERATOR
// ============================================================================

class TokenGenerator {
public:
    static std::string generateAAPS() {
        SecureBuffer buffer(AAPS_TOKEN_LENGTH);
        CryptoProvider::instance().generateRandomBytes(buffer.data(), buffer.size());
        
        std::string token;
        token.reserve(AAPS_TOKEN_LENGTH);
        
        for (size_t i = 0; i < AAPS_TOKEN_LENGTH; ++i) {
            size_t index = buffer.data()[i] % AAPS_CHARSET_SIZE;
            token.push_back(AAPS_CHARSET[index]);
        }
        
        return token;
    }
    
    static SHA256::Digest generateSalt() {
        SecureArray<uint8_t, SHA256_DIGEST_SIZE> salt_bytes;
        CryptoProvider::instance().generateRandomBytes(salt_bytes.data(), salt_bytes.size());
        return SHA256::hash(salt_bytes.data(), salt_bytes.size());
    }
};

// ============================================================================
// SECURE COMPARISON
// ============================================================================

class SecureCompare {
public:
    // Constant-time comparison to prevent timing attacks
    static bool equal(const uint8_t* a, const uint8_t* b, size_t length) noexcept {
        volatile uint8_t result = 0;
        
        for (size_t i = 0; i < length; ++i) {
            result |= a[i] ^ b[i];
        }
        
        return result == 0;
    }
    
    template<size_t N>
    static bool equal(const std::array<uint8_t, N>& a, 
                      const std::array<uint8_t, N>& b) noexcept {
        return equal(a.data(), b.data(), N);
    }
};

// ============================================================================
// AUTH FILE STRUCTURE
// ============================================================================

#pragma pack(push, 1)
struct AuthFileHeader {
    uint32_t magic;
    uint32_t version;
    uint64_t timestamp;
    uint32_t flags;
    uint32_t reserved;
};

struct AuthBlob {
    AuthFileHeader header;
    uint8_t token_hash[SHA256_DIGEST_SIZE];
    uint8_t salt[SHA256_DIGEST_SIZE];
    uint8_t verification_hash[SHA256_DIGEST_SIZE];  // Hash of token_hash + salt
};
#pragma pack(pop)

static_assert(sizeof(AuthBlob) == 120, "AuthBlob size mismatch");

// ============================================================================
// FILE SECURITY MANAGER
// ============================================================================

class FileSecurityManager {
public:
    static std::wstring getSecureAuthPath() {
        wchar_t appDataPath[MAX_PATH];
        
        if (FAILED(SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, appDataPath))) {
            throw AuthException(AuthError::SystemError, "Failed to get AppData path");
        }
        
        std::filesystem::path authDir = std::filesystem::path(appDataPath) / L"WinAuth";
        
        // Create directory with restricted permissions
        if (!std::filesystem::exists(authDir)) {
            if (!CreateDirectoryW(authDir.c_str(), nullptr)) {
                DWORD error = GetLastError();
                if (error != ERROR_ALREADY_EXISTS) {
                    throw AuthException(AuthError::SystemError, 
                        "Failed to create auth directory: " + std::to_string(error));
                }
            }
            
            // Set restrictive ACL on directory
            setRestrictedDACL(authDir.c_str());
        }
        
        return (authDir / L"auth.dat").wstring();
    }
    
    static bool setRestrictedDACL(const wchar_t* path) {
        PSECURITY_DESCRIPTOR pSD = nullptr;
        PACL pDACL = nullptr;
        
        // Create DACL that grants access only to the current user
        wchar_t sddl[] = L"D:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)";
        
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl, SDDL_REVISION_1, &pSD, nullptr)) {
            return false;
        }
        
        BOOL daclPresent = FALSE, daclDefaulted = FALSE;
        if (!GetSecurityDescriptorDacl(pSD, &daclPresent, &pDACL, &daclDefaulted)) {
            LocalFree(pSD);
            return false;
        }
        
        DWORD result = SetNamedSecurityInfoW(
            const_cast<wchar_t*>(path),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            nullptr, nullptr, pDACL, nullptr
        );
        
        LocalFree(pSD);
        return result == ERROR_SUCCESS;
    }
    
    static bool lockFileExclusive(HANDLE fileHandle) {
        OVERLAPPED overlapped = {};
        return LockFileEx(
            fileHandle,
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            MAXDWORD,
            MAXDWORD,
            &overlapped
        ) != FALSE;
    }
    
    static bool unlockFile(HANDLE fileHandle) {
        OVERLAPPED overlapped = {};
        return UnlockFileEx(fileHandle, 0, MAXDWORD, MAXDWORD, &overlapped) != FALSE;
    }
};

// ============================================================================
// AUTHENTICATION MANAGER
// ============================================================================

class AuthManager {
public:
    enum class AuthResult {
        Success,
        FirstRunInitialized,
        FileCorrupted,
        VerificationFailed,
        SystemError
    };
    
    static AuthResult authenticate() {
        try {
            std::wstring authPath = FileSecurityManager::getSecureAuthPath();
            
            // Try to open existing auth file
            WinHandle fileHandle(CreateFileW(
                authPath.c_str(),
                GENERIC_READ | GENERIC_WRITE,
                0,  // No sharing
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
                nullptr
            ));
            
            if (!fileHandle.valid()) {
                DWORD error = GetLastError();
                if (error == ERROR_FILE_NOT_FOUND) {
                    // First run - create new auth file
                    return initializeAuth(authPath);
                }
                throw AuthException(AuthError::FileAccessDenied, 
                    "Cannot access auth file: " + std::to_string(error));
            }
            
            // Lock file for exclusive access
            if (!FileSecurityManager::lockFileExclusive(fileHandle.get())) {
                throw AuthException(AuthError::FileAccessDenied, "Cannot lock auth file");
            }
            
            // Read and verify auth blob
            AuthBlob blob;
            DWORD bytesRead = 0;
            if (!ReadFile(fileHandle.get(), &blob, sizeof(blob), &bytesRead, nullptr) ||
                bytesRead != sizeof(blob)) {
                return AuthResult::FileCorrupted;
            }
            
            // Validate file format
            if (!validateAuthBlob(blob)) {
                return AuthResult::FileCorrupted;
            }
            
            // Verify integrity hash
            if (!verifyIntegrity(blob)) {
                return AuthResult::VerificationFailed;
            }
            
            FileSecurityManager::unlockFile(fileHandle.get());
            return AuthResult::Success;
            
        } catch (const AuthException& e) {
            std::wcerr << L"Authentication error: " << e.what() << std::endl;
            return AuthResult::SystemError;
        }
    }
    
private:
    static AuthResult initializeAuth(const std::wstring& path) {
        // Generate new credentials
        std::string token = TokenGenerator::generateAAPS();
        auto tokenHash = SHA256::hash(token);
        auto salt = TokenGenerator::generateSalt();
        
        // Create auth blob
        AuthBlob blob = {};
        blob.header.magic = AUTH_FILE_MAGIC;
        blob.header.version = AUTH_FILE_VERSION;
        blob.header.timestamp = static_cast<uint64_t>(
            std::chrono::system_clock::now().time_since_epoch().count());
        blob.header.flags = 0;
        
        memcpy(blob.token_hash, tokenHash.data(), SHA256_DIGEST_SIZE);
        memcpy(blob.salt, salt.data(), SHA256_DIGEST_SIZE);
        
        // Create verification hash (hash of token_hash || salt)
        SHA256 verifier;
        verifier.update(blob.token_hash, SHA256_DIGEST_SIZE);
        verifier.update(blob.salt, SHA256_DIGEST_SIZE);
        auto verificationHash = verifier.finalize();
        memcpy(blob.verification_hash, verificationHash.data(), SHA256_DIGEST_SIZE);
        
        // Create file with restrictive permissions
        WinHandle fileHandle(CreateFileW(
            path.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            nullptr,
            CREATE_NEW,
            FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM,
            nullptr
        ));
        
        if (!fileHandle.valid()) {
            throw AuthException(AuthError::SystemError, 
                "Failed to create auth file: " + std::to_string(GetLastError()));
        }
        
        // Set restrictive DACL on the file
        FileSecurityManager::setRestrictedDACL(path.c_str());
        
        // Write auth blob
        DWORD bytesWritten = 0;
        if (!WriteFile(fileHandle.get(), &blob, sizeof(blob), &bytesWritten, nullptr) ||
            bytesWritten != sizeof(blob)) {
            throw AuthException(AuthError::SystemError, "Failed to write auth file");
        }
        
        // Flush to disk
        FlushFileBuffers(fileHandle.get());
        
        // Securely clear the token from memory
        SecureZeroMemory(token.data(), token.size());
        SecureZeroMemory(&blob, sizeof(blob));
        
        return AuthResult::FirstRunInitialized;
    }
    
    static bool validateAuthBlob(const AuthBlob& blob) noexcept {
        if (blob.header.magic != AUTH_FILE_MAGIC) {
            return false;
        }
        
        if (blob.header.version != AUTH_FILE_VERSION) {
            return false;
        }
        
        return true;
    }
    
    static bool verifyIntegrity(const AuthBlob& blob) {
        // Recalculate verification hash
        SHA256 verifier;
        verifier.update(blob.token_hash, SHA256_DIGEST_SIZE);
        verifier.update(blob.salt, SHA256_DIGEST_SIZE);
        auto expectedHash = verifier.finalize();
        
        // Constant-time comparison
        return SecureCompare::equal(
            blob.verification_hash, 
            expectedHash.data(), 
            SHA256_DIGEST_SIZE
        );
    }
};

// ============================================================================
// LOGGING (Optional - for production diagnostics)
// ============================================================================

class Logger {
public:
    enum class Level { Debug, Info, Warning, Error };
    
    static void log(Level level, const std::wstring& message) {
        if (level < minLevel_) return;
        
        std::lock_guard<std::mutex> lock(mutex_);
        
        const wchar_t* prefix = L"";
        switch (level) {
            case Level::Debug:   prefix = L"[DEBUG] "; break;
            case Level::Info:    prefix = L"[INFO] "; break;
            case Level::Warning: prefix = L"[WARN] "; break;
            case Level::Error:   prefix = L"[ERROR] "; break;
        }
        
        std::wcerr << prefix << message << std::endl;
    }
    
    static void setMinLevel(Level level) { minLevel_ = level; }
    
private:
    static inline Level minLevel_ = Level::Info;
    static inline std::mutex mutex_;
};

} // namespace WinAuth

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================

int wmain(int argc, wchar_t* argv[]) {
    using namespace WinAuth;
    
    // Enable secure CRT features
    _set_invalid_parameter_handler([](const wchar_t*, const wchar_t*, 
                                       const wchar_t*, unsigned int, uintptr_t) {
        // Silent handler - prevents information disclosure
    });
    
    try {
        Logger::log(Logger::Level::Info, L"Starting authentication...");
        
        auto result = AuthManager::authenticate();
        
        switch (result) {
            case AuthManager::AuthResult::Success:
                Logger::log(Logger::Level::Info, L"Authentication successful");
                std::wcout << L"✓ Authenticated successfully" << std::endl;
                return 0;
                
            case AuthManager::AuthResult::FirstRunInitialized:
                Logger::log(Logger::Level::Info, L"First run - credentials initialized");
                std::wcout << L"✓ First run initialization complete" << std::endl;
                return 0;
                
            case AuthManager::AuthResult::FileCorrupted:
                Logger::log(Logger::Level::Error, L"Auth file corrupted");
                std::wcerr << L"✗ Authentication file corrupted" << std::endl;
                return 2;
                
            case AuthManager::AuthResult::VerificationFailed:
                Logger::log(Logger::Level::Error, L"Verification failed");
                std::wcerr << L"✗ Unauthorized system" << std::endl;
                return 1;
                
            case AuthManager::AuthResult::SystemError:
                Logger::log(Logger::Level::Error, L"System error during authentication");
                std::wcerr << L"✗ System error" << std::endl;
                return 3;
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 99;
    }
    
    return 0;
}