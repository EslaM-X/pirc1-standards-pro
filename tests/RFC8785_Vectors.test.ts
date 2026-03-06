import { PiRC100Validator } from '../src/core/PiRC100Validator';
import { SecurityManager } from '../src/SecurityManager';
/** @notice Integrity verified against Official RFC 8785 Reference Vectors */
import referenceVectors from './vectors/pirc100-reference.json';

/**
 * @file RFC8785_Vectors.test.ts
 * @module PiRC-100-Security-Audit
 * @description 
 * FINAL AUDIT COMPLIANCE SUITE. 
 * Engineered by EslaM-X to reach 100% Path Coverage (including catch blocks).
 * Strictly maintains existing naming conventions to prevent Frontend/Backend regressions.
 * @version 2.8.0
 */

describe('PiRC-100: RFC 8785 Deterministic Vectors & Integrity Compliance', () => {

  /**
   * @section Standard Compliance
   * Validates the core canonicalization against the official RFC 8785 vectors.
   */
  describe('Official Reference Vector Validation', () => {
    referenceVectors.test_cases.forEach((vector) => {
      test(`Reference Case ${vector.id}: Should match JCS canonical output`, () => {
        const result = PiRC100Validator.canonicalize(vector.input);
        expect(result).toBe(vector.expected_canonical);
      });
    });
  });

  /**
   * @section Deterministic Logic
   * Verifies that the hashing remains isomorphic and independent of object key insertion order.
   */
  describe('Deterministic Consistency & Hash Parity', () => {
    test('Vector 1: Key Insertion Order Parity', () => {
      const p1 = { a: 1, b: 2 };
      const p2 = { b: 2, a: 1 };
      expect(PiRC100Validator.generateDeterministicHash(p1))
        .toBe(PiRC100Validator.generateDeterministicHash(p2));
    });

    test('Vector 2: SecurityManager Isomorphic Signature Parity', () => {
      SecurityManager.rotateKeys();
      const d1 = { action: "login", status: true };
      const d2 = { status: true, action: "login" };
      expect(SecurityManager.generatePEPProof(d1).signature)
        .toBe(SecurityManager.generatePEPProof(d2).signature);
    });
  });

  /**
   * @section Resilience & Security Gates
   * Exhaustive testing of boundary conditions and internal error-handling paths.
   */
  describe('Resilience Testing & Security Gates', () => {
    
    test('Gate 1: Null and Undefined Protocol Handling', () => {
      expect(PiRC100Validator.canonicalize(null as any)).toBe("null"); 
      expect(PiRC100Validator.canonicalize(undefined as any)).toBe("");
    });

    test('Gate 2: Circular Reference Interception', () => {
      const nodeA: any = { name: "NodeA" };
      const nodeB: any = { name: "NodeB" };
      nodeA.link = nodeB;
      nodeB.link = nodeA; 
      
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      expect(() => PiRC100Validator.canonicalize(nodeA)).toThrow(); 
      spy.mockRestore();
    });

    /**
     * @target SecurityManager.ts:43 (Catch Block)
     * @description Forces the catch block in SecurityManager by defining a property 
     * that throws during the JSON stringification phase.
     */
    test('Gate 3: SecurityManager Internal Error Coverage', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      
      // Coverage: Empty object check
      expect(SecurityManager.generatePEPProof({} as any).signature).toBe("");

      // Coverage: Line 43 Catch via property explosion
      const poison = {};
      Object.defineProperty(poison, 'trigger', {
        get: () => { throw new Error("INTERNAL_AUDIT_EXHAUSTION"); },
        enumerable: true
      });
      expect(SecurityManager.generatePEPProof(poison as any).signature).toBe("");
      
      spy.mockRestore();
    });

    test('Gate 4: verifyPEPProof Logical Pathing', () => {
      SecurityManager.rotateKeys();
      const payload = { auth: "valid" };
      const proof = SecurityManager.generatePEPProof(payload);
      expect(SecurityManager.verifyPEPProof(payload, proof.signature, proof.version)).toBe(true);
      expect(SecurityManager.verifyPEPProof(payload, "", proof.version)).toBe(false);
    });

    test('Gate 7: Integrity Verification Edge Cases', () => {
      expect(PiRC100Validator.verifyIntegrity(null as any, "secret")).toBeNull();
      expect(typeof PiRC100Validator.verifyIntegrity({ a: 1 }, "secret")).toBe('string');
    });

    /**
     * @target PiRC100Validator.ts:63 & 83 (Catch Blocks)
     * @description Triggers internal exceptions within the canonicalization loop 
     * using the "Getter Bomb" technique to reach 100% statement/branch coverage.
     */
    test('Gate 8: Absolute Path Exhaustion (Line 63 & 83)', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      
      // 1. Coverage: Depth Limit (Line 34)
      const deep = (n: number): any => (n <= 0 ? { x: 1 } : { n: deep(n - 1) });
      expect(() => PiRC100Validator.canonicalize(deep(35))).toThrow("MAX_DEPTH_REACHED");

      // 2. Coverage: Internal Map Error (Line 63 & 83)
      const bomb = Object.create({}, {
        'critical_fail': { 
          get: () => { throw new Error("MAPPING_EXCEPTION"); }, 
          enumerable: true 
        }
      });
      // We wrap it in an object to trigger Stage 6 iteration
      expect(() => PiRC100Validator.canonicalize({ data: bomb })).toThrow();

      // 3. Coverage: Integrity Internal Catch (Line 103)
      const circular: any = { id: "audit" }; circular.self = circular; 
      expect(PiRC100Validator.verifyIntegrity(circular, "secret")).toBeNull();
      expect(PiRC100Validator.generateDeterministicHash(circular)).toBe("");

      // 4. Coverage: Array Normalization (Line 53)
      expect(PiRC100Validator.canonicalize([undefined])).toBe("[null]");
      
      spy.mockRestore();
    });
  });
});
