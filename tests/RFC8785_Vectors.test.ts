import { PiRC100Validator } from '../src/core/PiRC100Validator';
import { SecurityManager } from '../src/SecurityManager';
/** @notice Reference vectors for RFC 8785 compliance validation */
import referenceVectors from './vectors/pirc100-reference.json';

/**
 * @file RFC8785_Vectors.test.ts
 * @module PiRC100_Integrity_Audit
 * @description 
 * DEFINITIVE PATH EXHAUSTION SUITE.
 * Engineered by EslaM-X to reach 100% coverage across all security gates.
 * Targets precisely: SecurityManager.ts:43 and PiRC100Validator.ts:63.
 * @author EslaM-X | Lead Technical Architect
 * @version 2.9.0
 */

describe('PiRC-100: RFC 8785 Deterministic Vectors & Integrity Compliance', () => {

  /**
   * @group Compliance
   * Validates core canonicalization against official reference vectors.
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
   * @group Consistency
   * Ensures deterministic hash parity regardless of key insertion order.
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
   * @group Resilience
   * Stress-tests internal error handling and protocol resilience.
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
     * @target SecurityManager.ts:43
     * @description Forces the catch block by using an enumerable property that
     * throws during the hash processing phase.
     */
    test('Gate 3: SecurityManager Internal Error Coverage', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      
      // Target: Line 39
      expect(SecurityManager.generatePEPProof({} as any).signature).toBe("");

      // Target: Line 43 Catch
      const poison = Object.defineProperty({}, 'trigger', {
        get: () => { throw new Error("SIMULATED_INTERNAL_FAIL"); },
        enumerable: true
      });
      
      expect(SecurityManager.generatePEPProof(poison).signature).toBe("");
      spy.mockRestore();
    });

    test('Gate 4: verifyPEPProof Logic Coverage', () => {
      SecurityManager.rotateKeys();
      const payload = { auth: "valid" };
      const proof = SecurityManager.generatePEPProof(payload);
      expect(SecurityManager.verifyPEPProof(payload, proof.signature, proof.version)).toBe(true);
      expect(SecurityManager.verifyPEPProof(payload, "", proof.version)).toBe(false);
    });

    test('Gate 7: Integrity Verification Edge Cases', () => {
      expect(PiRC100Validator.verifyIntegrity(null as any, "secret")).toBeNull();
      expect(typeof PiRC100Validator.verifyIntegrity({ pirc: 100 }, "secret")).toBe('string');
    });

    /**
     * @target PiRC100Validator.ts:63
     * @description Forces the map iteration catch block to fire by injecting a 
     * non-serializable property descriptor in a nested structure.
     */
    test('Gate 8: Absolute Logical Path Exhaustion', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      
      // Target: Line 34 Depth
      const buildDeep = (l: number): any => (l <= 0 ? { x: 1 } : { n: buildDeep(l - 1) });
      expect(() => PiRC100Validator.canonicalize(buildDeep(35))).toThrow();

      // Target: Line 63 Mapping Catch
      const bomb = Object.defineProperty({}, 'error', {
        get: () => { throw new Error("MAP_ITERATION_FAIL"); },
        enumerable: true
      });
      expect(() => PiRC100Validator.canonicalize({ data: bomb })).toThrow();

      // Target: Line 103 Integrity Catch
      const circ: any = { id: 1 }; circ.self = circ; 
      expect(PiRC100Validator.verifyIntegrity(circ, "secret")).toBeNull();
      expect(PiRC100Validator.generateDeterministicHash(circ)).toBe("");

      // Target: Array Logic
      expect(PiRC100Validator.canonicalize([undefined])).toBe("[null]");
      
      spy.mockRestore();
    });
  });
});
