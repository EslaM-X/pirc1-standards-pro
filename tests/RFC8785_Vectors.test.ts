import { PiRC100Validator } from '../src/core/PiRC100Validator';
import { SecurityManager } from '../src/SecurityManager';
import referenceVectors from './vectors/pirc100-reference.json';

/**
 * @file RFC8785_Vectors.test.ts
 * @module PiRC-100_Gold_Standard_Audit
 * @version 2.5.2
 * @author EslaM-X | Lead Technical Architect
 * @description 
 * FINAL AUDIT SUITE - ARCHITECTED FOR 100% CODE COVERAGE.
 * Targets specific uncovered lines: SM (62) | Validator (83, 103, 119).
 * Utilizes architectural fault injection while preserving all public API contracts.
 */

describe('PiRC-100: RFC 8785 Deterministic Vectors & Integrity Compliance', () => {

  beforeEach(() => {
    // State Reset: Ensure a clean environment for every test cycle
    jest.clearAllMocks();
    jest.restoreAllMocks();
    
    // Safety Switch: Ensure fault injection is disabled by default
    (PiRC100Validator as any).setFaultInjection(false);
    (SecurityManager as any).setFaultInjection(false);
  });

  /** * SECTION 1: OFFICIAL RFC VECTORS
   * Validates core logic against the immutable JCS test suite.
   */
  describe('Official Reference Vector Validation', () => {
    referenceVectors.test_cases.forEach((vector: any) => {
      test(`Reference Case ${vector.id}: Standard Compliance`, () => {
        expect(PiRC100Validator.canonicalize(vector.input)).toBe(vector.expected || vector.expected_canonical);
      });
    });
  });

  /** * SECTION 2: DETERMINISM & CRYPTOGRAPHIC PARITY
   */
  describe('Deterministic Consistency & Hash Parity', () => {
    test('Test 5: Key Insertion Order Stability', () => {
      const p1 = { a: 1, b: 2 };
      const p2 = { b: 2, a: 1 };
      expect(PiRC100Validator.generateDeterministicHash(p1)).toBe(PiRC100Validator.generateDeterministicHash(p2));
    });

    test('Test 6: Isomorphic Signature Stability', () => {
      SecurityManager.rotateKeys();
      const d = { status: "active" };
      expect(SecurityManager.generatePEPProof(d).signature).toBeDefined();
    });
  });

  /** * SECTION 3: RESILIENCE & 100% COVERAGE EXHAUSTION
   * Directly targets the remaining uncovered lines in the audit log.
   */
  describe('Resilience Testing & Coverage Completion', () => {
    
    test('Test 7: Circular Reference Guard (Infinite Loop Prevention)', () => {
      const circ: any = {}; circ.a = circ;
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      expect(() => PiRC100Validator.canonicalize(circ)).toThrow();
      spy.mockRestore();
    });

    test('Test 8: Primitive Handling (Null/Undefined)', () => {
      expect(PiRC100Validator.canonicalize(null as any)).toBe("null");
      expect(PiRC100Validator.canonicalize(undefined as any)).toBe("");
    });

    test('Test 10: Deep Nesting Limit Enforcement', () => {
      const deep = (n: number): any => n <= 0 ? {x:1} : {n: deep(n-1)};
      expect(() => PiRC100Validator.canonicalize(deep(35))).toThrow("MAX_DEPTH_REACHED");
    });

    /**
     * @target SecurityManager.ts:Line 62 (The Catch Block)
     * Triggers the simulated security halt to cover the error recovery path.
     */
    test('Test 12: SecurityManager Internal Catch Recovery (Line 62)', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      (SecurityManager as any).setFaultInjection(true); // Architect's Overrule
      
      const result = SecurityManager.generatePEPProof({ secure: true });
      expect(result.signature).toBe(""); // Verify fail-soft logic
      
      (SecurityManager as any).setFaultInjection(false);
      spy.mockRestore();
    });

    /**
     * @target PiRC100Validator.ts:Line 83 (Canonicalize Catch)
     */
    test('Test 13: Validator Protocol Error Handling (Line 83)', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      (PiRC100Validator as any).setFaultInjection(true); 
      
      expect(() => PiRC100Validator.canonicalize({ any: 1 })).toThrow();
      expect(spy).toHaveBeenCalled(); 
      
      (PiRC100Validator as any).setFaultInjection(false);
      spy.mockRestore();
    });

    /**
     * @target PiRC100Validator.ts:Line 103 (Deterministic Hash Catch)
     */
    test('Test 16: Hash Generation Fault Tolerance (Line 103)', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      (PiRC100Validator as any).setFaultInjection(true);
      
      expect(PiRC100Validator.generateDeterministicHash({ test: 1 })).toBe("");
      
      (PiRC100Validator as any).setFaultInjection(false);
      spy.mockRestore();
    });

    /**
     * @target PiRC100Validator.ts:Line 119 (Integrity Catch)
     */
    test('Test 15: Integrity Verification Exception Path (Line 119)', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      (PiRC100Validator as any).setFaultInjection(true);
      
      expect(PiRC100Validator.verifyIntegrity({ test: 1 }, "key")).toBeNull();
      
      (PiRC100Validator as any).setFaultInjection(false);
      spy.mockRestore();
    });

    test('Test 17: Full Integrity Success Chain', () => {
      const payload = { auth: "granted", id: 101 };
      const proof = SecurityManager.generatePEPProof(payload);
      expect(SecurityManager.verifyPEPProof(payload, proof.signature, proof.version)).toBe(true);
    });

    test('Test 20: Array Normalization & String Escaping', () => {
      expect(PiRC100Validator.canonicalize([undefined, 1])).toBe("[null,1]");
      expect(PiRC100Validator.canonicalize("EslaM-X")).toBe("\"EslaM-X\"");
    });
  });
});
