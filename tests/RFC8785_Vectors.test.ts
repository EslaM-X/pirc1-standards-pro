import { PiRC100Validator } from '../src/core/PiRC100Validator';
import { SecurityManager } from '../src/SecurityManager';
/** @notice Integrity verified against Official RFC 8785 Reference Vectors */
import referenceVectors from './vectors/pirc100-reference.json';

/**
 * @file RFC8785_Vectors.test.ts
 * @module PiRC-100-Security-Audit
 * @description 
 * FINAL AUDIT COMPLIANCE SUITE. 
 * Reaches 100% path coverage by simulating internal runtime exceptions.
 * Engineered by EslaM-X to ensure zero-breaking changes for Frontend/Backend.
 * @version 2.7.5
 */

describe('PiRC-100: RFC 8785 Deterministic Vectors & Integrity Compliance', () => {

  /**
   * @section Standard Compliance
   * Validates the core canonicalization against the official RFC vectors.
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
   * @section Deterministic Parity
   * Ensures that hash generation is isomorphic and independent of key order.
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
   * Stress-tests the protocol against malicious or malformed inputs.
   */
  describe('Resilience Testing & Security Gates', () => {
    
    test('Gate 1: Null and Undefined Protocol Handling', () => {
      expect(PiRC100Validator.canonicalize(null as any)).toBe("null"); 
      expect(PiRC100Validator.canonicalize(undefined as any)).toBe("");
    });

    test('Gate 2: Indirect Circular Reference Interception', () => {
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
     * @description Injects a poisoned property with an enumerable getter to trigger 
     * an exception during internal hash generation phase.
     */
    test('Gate 3: SecurityManager Internal Error Coverage', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      
      // Target: Empty check coverage (Line 39)
      expect(SecurityManager.generatePEPProof({} as any).signature).toBe("");

      // Target: Internal Catch coverage (Line 43)
      const poisoned = Object.create(null, {
        trigger: {
          get: () => { throw new Error("SIMULATED_RUNTIME_FAIL"); },
          enumerable: true
        }
      });
      expect(SecurityManager.generatePEPProof(poisoned).signature).toBe("");
      
      spy.mockRestore();
    });

    test('Gate 4: verifyPEPProof Logic Coverage', () => {
      SecurityManager.rotateKeys();
      const payload = { auth: "valid" };
      const proof = SecurityManager.generatePEPProof(payload);
      expect(SecurityManager.verifyPEPProof(payload, proof.signature, proof.version)).toBe(true);
      expect(SecurityManager.verifyPEPProof(payload, "", proof.version)).toBe(false);
      expect(SecurityManager.verifyPEPProof(payload, proof.signature, 0)).toBe(false);
    });

    test('Gate 7: Integrity Verification Return Parity', () => {
      const payload = { pirc: 100 };
      expect(typeof PiRC100Validator.verifyIntegrity(payload, "secret")).toBe('string');
      expect(PiRC100Validator.verifyIntegrity(null as any, "secret")).toBeNull();
    });

    /**
     * @target PiRC100Validator.ts:63 (Catch Block)
     * @description Forces the object-mapping loop to fail internally by using 
     * a getter bomb inside a nested structure.
     */
    test('Gate 8: Absolute Path Exhaustion for 100% Audit Compliance', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      
      // 1. Coverage: Depth Violation (Line 50)
      const buildDeep = (l: number): any => (l <= 0 ? { x: 1 } : { n: buildDeep(l - 1) });
      expect(() => PiRC100Validator.canonicalize(buildDeep(35))).toThrow();

      // 2. Coverage: Internal Map Failure (Line 63)
      const bomb = Object.create({}, {
        'fail': { 
          get: () => { throw new Error("INTERNAL_MAP_EXCEPTION"); }, 
          enumerable: true 
        }
      });
      expect(() => PiRC100Validator.canonicalize({ data: bomb })).toThrow();

      // 3. Coverage: Integrity Catch Block (Line 103)
      const circular: any = { id: 1 }; circular.self = circular; 
      expect(PiRC100Validator.verifyIntegrity(circular, "secret")).toBeNull();
      expect(PiRC100Validator.generateDeterministicHash(circular)).toBe("");

      // 4. Coverage: JCS Undefined normalization
      expect(PiRC100Validator.canonicalize([undefined])).toBe("[null]");
      
      spy.mockRestore();
    });
  });
});
