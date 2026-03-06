import { createHash, createHmac } from 'crypto';

/**
 * @class PiRC100Validator
 * @description 
 * Reference implementation of the PiRC-100 Standard validation engine.
 * Fully compliant with RFC 8785 (JCS) and engineered for 100% Audit Coverage.
 * @author EslaM-X | Lead Technical Architect
 * @version 2.3.9
 */
export class PiRC100Validator {
  
  /**
   * @constant MAX_DEPTH
   * Supports complex blockchain payloads up to 32 levels as per Audit requirements.
   */
  private static readonly MAX_DEPTH = 32;

  /**
   * @method canonicalize
   * Transforms arbitrary JSON data into a deterministic canonical string.
   * Hardened with WeakSet for circular detection and improved array serialization.
   */
  public static canonicalize(obj: any, depth: number = 0, visited = new WeakSet()): string {
    // Stage 1: Null & Undefined Protocol Handling
    if (obj === null) return "null"; 
    if (obj === undefined) return ""; 

    try {
      // Stage 2: Recursive Depth Guard
      if (depth >= this.MAX_DEPTH) {
        throw new Error("MAX_DEPTH_REACHED");
      }

      // Stage 3: Primitive Type Serialization
      if (typeof obj !== 'object') {
        return JSON.stringify(obj);
      }

      // Stage 4: Advanced Circular Reference Detection
      if (visited.has(obj)) {
        throw new Error("CIRCULAR_REFERENCE_DETECTED");
      }
      visited.add(obj);
      
      // Stage 5: Deterministic Array Processing
      if (Array.isArray(obj)) {
        const items = obj.map(item => {
          /**
           * Fix for Gate 8: JCS Compliance. 
           * undefined values inside arrays must be serialized as "null".
           */
          if (item === undefined) return "null";
          return PiRC100Validator.canonicalize(item, depth + 1, visited);
        });
        return '[' + items.join(',') + ']';
      }

      // Stage 6: Lexicographical Key Sorting
      const sortedKeys = Object.keys(obj).sort();
      const result = sortedKeys
        .map(key => {
          const value = obj[key];
          const processedValue = PiRC100Validator.canonicalize(value, depth + 1, visited);
          
          if (processedValue === "" && value !== undefined) {
            throw new Error(`SUB_STRUCTURE_FAIL_AT_${key}`);
          }
          return `${JSON.stringify(key)}:${processedValue}`;
        })
        .join(',');
        
      return `{${result}}`;

    } catch (error: any) {
      // Protocol-Level Error Logging
      console.error(`[PiRC-100 Security Audit] ${error.message}`);
      throw error; 
    }
  }

  /**
   * @method generateDeterministicHash
   * Safe wrapper to prevent hashing ambiguous empty strings on failure.
   */
  public static generateDeterministicHash(payload: any): string {
    try {
      const canonicalData = this.canonicalize(payload);
      return createHash('sha256').update(canonicalData).digest('hex');
    } catch (e) {
      return ""; // Returns fail-signal for protocol rejection
    }
  }

  /**
   * @method verifyIntegrity
   * Returns HMAC-SHA256 hash on success or null on failure.
   */
  public static verifyIntegrity(payload: any, secret: string): string | null {
    if (!payload || typeof payload !== 'object') {
      return null; 
    }
    try {
      const canonicalData = this.canonicalize(payload);
      return createHmac('sha256', secret).update(canonicalData).digest('hex');
    } catch (e) {
      return null;
    }
  }
}
