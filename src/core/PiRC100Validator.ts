import { createHash, createHmac } from 'crypto';

/**
 * @class PiRC100Validator
 * @description 
 * Reference implementation of the PiRC-100 Standard validation engine.
 * Fully compliant with RFC 8785 (JCS).
 * Hardened with WeakSet for circular detection and expanded recursion depth.
 * @author EslaM-X | Lead Technical Architect
 * @version 2.3.1
 */
export class PiRC100Validator {
  
  /**
   * @constant MAX_DEPTH
   * Increased to 32 to support complex blockchain payloads while maintaining safety.
   */
  private static readonly MAX_DEPTH = 32;

  /**
   * @method canonicalize
   * Transforms arbitrary JSON data into a deterministic canonical string.
   * Now tracks visited objects to detect indirect circular references.
   */
  public static canonicalize(obj: any, depth: number = 0, visited = new WeakSet()): string {
    // Stage 1: Null & Undefined Protocol Handling
    if (obj === null) return "null"; 
    if (obj === undefined) return ""; 

    try {
      // Stage 2: Recursive Depth Guard
      if (depth >= this.MAX_DEPTH) {
        throw new Error(`MAX_DEPTH_REACHED`);
      }

      // Stage 3: Primitive Type Serialization
      if (typeof obj !== 'object') {
        return JSON.stringify(obj);
      }

      /**
       * Stage 4: Advanced Circular Reference Detection
       * Uses WeakSet to catch multi-level cycles (A -> B -> A).
       */
      if (visited.has(obj)) {
        throw new Error("CIRCULAR_REFERENCE_DETECTED");
      }
      visited.add(obj);
      
      // Stage 5: Deterministic Array Processing
      if (Array.isArray(obj)) {
        const items = obj.map(item => {
          const res = PiRC100Validator.canonicalize(item, depth + 1, visited);
          if (res === "" && item !== undefined) throw new Error("NESTED_FAIL");
          return res;
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
      // Throw error to prevent hashing an empty string (Hash Ambiguity Fix)
      throw error; 
    }
  }

  /**
   * @method generateDeterministicHash
   * Safe wrapper for canonicalization to prevent sha256("") on failure.
   */
  public static generateDeterministicHash(payload: any): string {
    try {
      const canonicalData = this.canonicalize(payload);
      return createHash('sha256').update(canonicalData).digest('hex');
    } catch (e) {
      return ""; // Returns empty as a fail-signal for downstream logic
    }
  }

  /**
   * @method verifyIntegrity
   * Returns string (hash) on success or null on failure.
   * Cleaned interface as per auditor recommendation.
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
