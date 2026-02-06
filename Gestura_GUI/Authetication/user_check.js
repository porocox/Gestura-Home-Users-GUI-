"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const os = require("os");

// --- Configuration ---
const CONFIG = Object.freeze({
  APP_NAME: "Gestura",
  SESSION_DIR: "Gestura",
  SESSION_FILE: "sys.secure.session",
  // Crypto Settings
  ALGORITHM: "aes-256-gcm",
  KEY_ITERATIONS: 100000,
  KEY_LENGTH: 32,
  DIGEST: "sha512",
  // Logging
  LOG_DIR_NAME: "LOGS"
});

/**
 * Error for Auth Failures
 */
class GesturaAuthError extends Error {
  constructor(message, code) {
    super(message);
    this.name = "GesturaAuthError";
    this.code = code;
  }
}

/**
 * System Logger
 * Principle: Uses WriteStreams for memory efficiency (buffering) rather than 
 * blocking sync writes. 
 */
class SystemLogger {
  #logStream;
  #logDir;

  constructor() {
    // 1. Determine Root Path (Where the script is running)
    const rootDir = path.resolve(__dirname);
    this.#logDir = path.join(rootDir, CONFIG.LOG_DIR_NAME);

    // 2. Ensure Logs Directory Exists
    if (!fs.existsSync(this.#logDir)) {
      fs.mkdirSync(this.#logDir, { recursive: true });
    }

    // 3. Create Daily Log File (e.g., 2023-10-25.log)
    const dateStr = new Date().toISOString().split("T")[0];
    const logFile = path.join(this.#logDir, `${dateStr}.log`);

    // 4. Open Stream (flags: 'a' for append)
    this.#logStream = fs.createWriteStream(logFile, { flags: "a", encoding: "utf8" });
  }

  write(level, message) {
    if (!this.#logStream || this.#logStream.destroyed) return;

    const timestamp = new Date().toISOString();
    const logEntry = `[${timestamp}] [${level}] ${message}\n`;
    
    // Writes to buffer, flushes to disk automatically. 
    // Non-blocking I/O prevents memory spikes during heavy operations.
    this.#logStream.write(logEntry);
  }

  info(msg) { this.write("INFO", msg); }
  warn(msg) { this.write("WARN", msg); }
  error(msg) { this.write("ERROR", msg); }

  close() {
    if (this.#logStream) {
      this.#logStream.end();
      this.#logStream = null; // Dereference for GC
    }
  }
}

/**
 * Authentication System
 */
class GesturaSystemAuth {
  // Native Private Fields (Encapsulation Principle)
  // These cannot be accessed outside this class, protecting memory state.
  #baseDir;
  #storageDir;
  #sessionPath;
  #isAuthenticated = false;
  #sessionData = null;
  #logger;

  constructor() {
    if (process.platform !== "win32") {
      throw new GesturaAuthError("GesturaAuth supports Windows only", "PLATFORM_ERR");
    }

    this.#logger = new SystemLogger();
    
    // Use AppData for secure storage (User specific), but Logs in Root (as requested)
    this.#baseDir = process.env.LOCALAPPDATA || path.join(os.homedir(), "AppData", "Local");
    this.#storageDir = path.join(this.#baseDir, CONFIG.SESSION_DIR);
    this.#sessionPath = path.join(this.#storageDir, CONFIG.SESSION_FILE);
  }

  // --- Internal Helpers ---

  #deriveEncryptionKey() {
    // Unique fingerprint for this machine + user
    const machineId = `${os.hostname()}-${os.userInfo().username}-${os.arch()}`;
    const salt = Buffer.from(machineId + "GESTURA_SALT_V2"); 
    
    // PBKDF2: Computationally expensive to prevent brute force
    const key = crypto.pbkdf2Sync(
      machineId,
      salt,
      CONFIG.KEY_ITERATIONS,
      CONFIG.KEY_LENGTH,
      CONFIG.DIGEST
    );
    
    return key;
  }

  #ensureStorage() {
    if (!fs.existsSync(this.#storageDir)) {
      // mode: 0o700 = Read/Write/Execute for Owner ONLY.
      fs.mkdirSync(this.#storageDir, { recursive: true, mode: 0o700 });
    }
  }

  // --- Encryption/Decryption ---

  #encrypt(text) {
    let key = this.#deriveEncryptionKey();
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(CONFIG.ALGORITHM, key, iv);
    
    let encrypted = cipher.update(text, "utf8", "hex");
    encrypted += cipher.final("hex");
    const authTag = cipher.getAuthTag().toString("hex");

    // Memory Management: Nullify key immediately after use
    key = null; 

    return `${iv.toString("hex")}:${authTag}:${encrypted}`;
  }

  #decrypt(encryptedData) {
    const parts = encryptedData.split(":");
    if (parts.length !== 3) throw new Error("Invalid session format");

    const [ivHex, authTagHex, contentHex] = parts;
    
    let key = this.#deriveEncryptionKey();
    const iv = Buffer.from(ivHex, "hex");
    const authTag = Buffer.from(authTagHex, "hex");
    
    const decipher = crypto.createDecipheriv(CONFIG.ALGORITHM, key, iv);
    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(contentHex, "hex", "utf8");
    decrypted += decipher.final("utf8");
    
    // Memory Management: Nullify key
    key = null;

    return decrypted;
  }

  // --- Session Management ---

  #createSession() {
    this.#ensureStorage();
    
    const payload = JSON.stringify({
      uid: crypto.randomUUID(),
      created: Date.now(),
      user: os.userInfo().username
    });

    const encryptedContent = this.#encrypt(payload);

    // mode: 0o600 = Read/Write for Owner ONLY
    fs.writeFileSync(this.#sessionPath, encryptedContent, { encoding: "utf8", mode: 0o600 });
    
    this.#isAuthenticated = true;
    this.#sessionData = JSON.parse(payload);
    
    this.#logger.info(`New secure session created: ${this.#sessionData.uid}`);
  }

  #validateSession() {
    if (!fs.existsSync(this.#sessionPath)) return false;

    try {
      const fileContent = fs.readFileSync(this.#sessionPath, "utf8");
      const decrypted = this.#decrypt(fileContent);
      const data = JSON.parse(decrypted);

      if (data.user !== os.userInfo().username) {
        this.#logger.warn("Session user mismatch detected. Invalidating.");
        return false;
      }

      this.#sessionData = data;
      this.#logger.info("Session restored successfully.");
      return true;
    } catch (err) {
      this.#logger.error(`Session corruption detected: ${err.message}`);
      return false;
    }
  }

  // --- Public API ---

  boot() {
    this.#logger.info("System booting...");
    try {
      if (this.#validateSession()) {
        this.#isAuthenticated = true;
      } else {
        this.logout(); 
        this.#createSession();
      }
    } catch (err) {
      this.#logger.error(`Boot critical failure: ${err.message}`);
      throw new GesturaAuthError(`Boot failed: ${err.message}`, "BOOT_ERR");
    }
  }

  enforce() {
    if (!this.#isAuthenticated) {
      const msg = "Unauthorized system access blocked";
      this.#logger.warn(msg);
      throw new GesturaAuthError(msg, "AUTH_DENIED");
    }
  }

  logout() {
    if (fs.existsSync(this.#sessionPath)) {
      try {
        fs.unlinkSync(this.#sessionPath);
        this.#logger.info("Session file deleted.");
      } catch (e) {
        this.#logger.error(`Failed to delete session file: ${e.message}`);
      }
    }
    
    // Memory Management: Clear state
    this.#isAuthenticated = false;
    this.#sessionData = null;
  }

  status() {
    return Object.freeze({
      authenticated: this.#isAuthenticated,
      user: this.#sessionData ? this.#sessionData.user : null,
      sessionId: this.#sessionData ? this.#sessionData.uid : null
    });
  }

  runSecure(task) {
    this.enforce();
    this.#logger.info("Executing secure task.");
    return task();
  }

  /**
   * MEMORY MANAGEMENT: Graceful Shutdown
   * Call this when the application exits to flush logs and clear memory.
   */
  dispose() {
    this.#logger.info("System shutting down. Disposing resources.");
    this.#sessionData = null; // Clear sensitive data from heap
    this.#isAuthenticated = false;
    this.#logger.close(); // Close file streams
  }
}

// --- Main Execution ---

const AuthSystem = new GesturaSystemAuth();

// Handle Process Exit for Memory Cleanup
process.on('SIGINT', () => {
  AuthSystem.dispose();
  process.exit();
});

function main() {
  try {
    console.log("--> Booting System...");
    AuthSystem.boot();

    console.log("--> Status:", AuthSystem.status());

    const result = AuthSystem.runSecure(() => {
      // Simulate heavy work
      const heavyObj = {
        engine: "Gestura",
        state: "RUNNING",
        pid: process.pid,
        timestamp: Date.now()
      };
      return heavyObj;
    });

    console.log("--> Result:", result);

  } catch (error) {
    console.error("!!! CRITICAL FAILURE !!!", error.message);
    process.exit(1);
  } finally {
    // Ensure resources are freed even after execution
    console.log("--> Cleaning up...");
    AuthSystem.dispose();
  }
}

main();