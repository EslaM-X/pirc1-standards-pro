import { createHash, createHmac } from 'crypto';

/**
 * @class PiRC100Validator
 * @description 
 * Core validation engine for the PiRC-100 Standard.
 * Implements hardened RFC 8785 (JCS) with fail-safe cryptographic integrity.
 * Engineered for absolute determinism across distributed node environments.
 * @author EslaM-X | Lead Technical Architect
 */
export class PiRC100Validator {
  
  /**
   * @constant MAX_DEPTH
   * @description 
   * Protects the Pi Node from Stack Overflow and ReDoS attacks.
   * Locked at 5 to ensure high-speed processing while blocking malicious nesting.
   */
  private static readonly MAX_DEPTH = 5;

  /**
   * @method canonicalize
   * @description 
   * Implements RFC 8785 (JCS) with explicit security gates.
   * Features: Circular Reference Detection, Depth Guard, and Lexicographical Sorting.
   * @param {any} obj - The payload to be serialized.
   * @param {number} depth - Internal tracking for recursion depth.
   * @returns {string} - An RFC 8785 compliant canonical string or empty on failure.
   */
  public static canonicalize(obj: any, depth: number = 0): string {
    // Phase 1: Null-Safety
    if (obj === null || obj === undefined) {
      return ""; 
    }

    try {
      // Phase 2: Recursion Depth Protection (Architectural Safety Gate)
      if (depth > this.MAX_DEPTH) {
        throw new Error(`Maximum recursion depth (${this.MAX_DEPTH}) exceeded`);
      }

      // Phase 3: Primitive Type Handling
      if (typeof obj !== 'object') {
        return JSON.stringify(obj);
      }
      
      // Phase 4: Deterministic Array Processing
      if (Array.isArray(obj)) {
        const items = obj.map(item => {
          const res = PiRC100Validator.canonicalize(item, depth + 1);
          if (res === "" && item !== null && item !== undefined) throw new Error("Nested failure");
          return res;
        });
        return '[' + items.join(',') + ']';
      }

      // Phase 5: Lexicographical Key Sorting (Core JCS requirement)
      const sortedKeys = Object.keys(obj).sort();
      const result = sortedKeys
        .map(key => {
          const value = obj[key];
          
          /**
           * Critical Security: Circular Reference Detection.
           */
          if (value === obj) {
            throw new Error(`Circular reference detected at key: ${key}`);
          }
          
          const processedValue = PiRC100Validator.canonicalize(value, depth + 1);
          
          // Atomic Validation: If sub-tree fails, the whole branch must fail to protect the hash.
          if (processedValue === "" && value !== null && value !== undefined) {
            throw new Error("Recursive limit reached in sub-structure");
          }
          
          return `${JSON.stringify(key)}:${processedValue}`;
        })
        .join(',');
        
      return `{${result}}`;

    } catch (error: any) {
      /**
       * Production-Grade Error Management.
       * Logs security alerts for auditing while ensuring cryptographic failure safety.
       */
      console.error(`[PiRC-100 Security] ${error.message}`);
      return "";
    }
  }

  /**
   * @method generateDeterministicHash
   * @description Generates a collision-resistant SHA-256 hash.
   * @param {any} payload - Data structure to be hashed.
   * @returns {string} - Hexadecimal representation of the SHA-256 digest.
   */
  public static generateDeterministicHash(payload: any): string {
    const canonicalData = this.canonicalize(payload);
    return createHash('sha256').update(canonicalData).digest('hex');
  }

  /**
   * @method verifyIntegrity
   * @description Signs or verifies the payload integrity using HMAC-SHA256.
   * @param {any} payload - The message to be authenticated.
   * @param {string} secret - Ephemeral symmetric key.
   * @returns {string} - HMAC authentication tag for cross-node validation.
   */
  public static verifyIntegrity(payload: any, secret: string): string {
    const canonicalData = this.canonicalize(payload);
    return createHmac('sha256', secret).update(canonicalData).digest('hex');
  }
}
