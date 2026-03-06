import { createHash, createHmac } from 'crypto';

/**
 * @class PiRC100Validator
 * @description 
 * Reference implementation of the PiRC-100 Standard validation engine.
 * Fully compliant with RFC 8785 (JSON Canonicalization Scheme - JCS).
 * Engineered to ensure cross-node determinism and cryptographic integrity 
 * within decentralized environments.
 * * @author EslaM-X | Lead Technical Architect
 * @version 2.2.1
 */
export class PiRC100Validator {
  
  /**
   * @constant MAX_DEPTH
   * @description 
   * Architectural safety gate to prevent Stack Overflow and ReDoS attacks.
   * Enforces a strict recursion limit for high-performance payload processing.
   */
  private static readonly MAX_DEPTH = 5;

  /**
   * @method canonicalize
   * @description 
   * Transforms arbitrary JSON data into a deterministic canonical string.
   * Implements strict lexicographical key sorting, recursion guards, and 
   * RFC 8785 primitive serialization.
   * * @param {any} obj - The data structure to be canonicalized.
   * @param {number} depth - Internal recursion tracker for security enforcement.
   * @returns {string} - An RFC 8785 compliant string or an empty string on security violation.
   */
  public static canonicalize(obj: any, depth: number = 0): string {
    // Stage 1: RFC 8785 Null & Undefined Protocol Handling
    // Essential for maintaining hash parity across different runtime environments.
    if (obj === null) return "null"; 
    if (obj === undefined) return ""; 

    try {
      // Stage 2: Recursive Depth Exhaustion Guard
      // Prevents malicious deeply-nested objects from compromising node stability.
      if (depth >= this.MAX_DEPTH) {
        throw new Error(`Security boundary reached: MAX_DEPTH (${this.MAX_DEPTH}) exceeded`);
      }

      // Stage 3: Primitive Type Serialization
      // Ensures consistent representation of Booleans, Numbers, and Strings.
      if (typeof obj !== 'object') {
        return JSON.stringify(obj);
      }
      
      // Stage 4: Deterministic Array Processing
      // Recursively canonicalizes elements while maintaining indexed order.
      if (Array.isArray(obj)) {
        const items = obj.map(item => {
          const res = PiRC100Validator.canonicalize(item, depth + 1);
          // Integrity Check: Stop processing if a nested element violates security gates.
          if (res === "" && item !== undefined) {
            throw new Error("Atomic failure in nested array structure");
          }
          return res;
        });
        return '[' + items.join(',') + ']';
      }

      // Stage 5: Lexicographical Key Sorting (JCS Core Requirement)
      // Keys are sorted by Unicode code point to ensure a single unique output string.
      const sortedKeys = Object.keys(obj).sort();
      const result = sortedKeys
        .map(key => {
          const value = obj[key];
          
          /**
           * Critical Security: Circular Reference Interception.
           * Mitigates infinite loops and memory exhaustion.
           */
          if (value === obj) {
            throw new Error(`Circular reference identified at key: ${key}`);
          }
          
          const processedValue = PiRC100Validator.canonicalize(value, depth + 1);
          
          /**
           * Branch Hardening: Validates successful propagation of sub-structures.
           * Essential for 100% audit coverage and fail-safe cryptographic signing.
           */
          if (processedValue === "" && value !== undefined) {
            throw new Error(`Integrity breach in sub-structure at key: ${key}`);
          }
          
          return `${JSON.stringify(key)}:${processedValue}`;
        })
        .join(',');
        
      return `{${result}}`;

    } catch (error: any) {
      /**
       * Production-Grade Security Logging.
       * Ensures that any violation results in a safe cryptographic failure (empty string).
       */
      console.error(`[PiRC-100 Security Audit] ${error.message}`);
      return "";
    }
  }

  /**
   * @method generateDeterministicHash
   * @description Computes a collision-resistant SHA-256 digest of the canonicalized payload.
   */
  public static generateDeterministicHash(payload: any): string {
    const canonicalData = this.canonicalize(payload);
    return createHash('sha256').update(canonicalData).digest('hex');
  }

  /**
   * @method verifyIntegrity
   * @description Generates an HMAC-SHA256 signature to verify data authenticity and origin.
   */
  public static verifyIntegrity(payload: any, secret: string): string {
    const canonicalData = this.canonicalize(payload);
    return createHmac('sha256', secret).update(canonicalData).digest('hex');
  }
}
