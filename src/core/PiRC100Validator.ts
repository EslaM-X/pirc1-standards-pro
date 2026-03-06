import { createHash, createHmac } from 'crypto';

/**
 * @class PiRC100Validator
 * @description Core validation engine for the PiRC-100 Standard.
 * Implements deterministic serialization and cryptographic integrity mapping.
 * @author EslaM-X
 */
export class PiRC100Validator {
  
  /**
   * @method canonicalize
   * @description Implements RFC 8785 (JSON Canonicalization Scheme - JCS).
   * Ensures absolute determinism by enforcing lexicographical key sorting 
   * and consistent primitive formatting across distributed nodes.
   * @param {any} obj - The payload to be serialized.
   * @returns {string} - An RFC 8785 compliant canonical string.
   */
  public static canonicalize(obj: any): string {
    if (obj === null || typeof obj !== 'object') {
      return JSON.stringify(obj);
    }
    
    if (Array.isArray(obj)) {
      return '[' + obj.map(PiRC100Validator.canonicalize).join(',') + ']';
    }

    // Enforce lexicographical key sorting to guarantee cross-environment hash consistency
    const sortedKeys = Object.keys(obj).sort();
    const result = sortedKeys
      .map(key => `${JSON.stringify(key)}:${PiRC100Validator.canonicalize(obj[key])}`)
      .join(',');
      
    return `{${result}}`;
  }

  /**
   * @method generateDeterministicHash
   * @description Generates a collision-resistant SHA-256 hash.
   * Utilizes JCS canonicalization to prevent hash divergence caused by key-order mutations.
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
   * Designed for high-speed Application-Layer security during handshake procedures.
   * @param {any} payload - The message to be authenticated.
   * @param {string} secret - Ephemeral symmetric key derived via ECDH.
   * @returns {string} - HMAC authentication tag for cross-node validation.
   */
  public static verifyIntegrity(payload: any, secret: string): string {
    const canonicalData = this.canonicalize(payload);
    return createHmac('sha256', secret).update(canonicalData).digest('hex');
  }
}
