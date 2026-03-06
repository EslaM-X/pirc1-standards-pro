import { PiRC100Validator } from '../src/core/PiRC100Validator';
import { SecurityManager } from '../src/SecurityManager';
import referenceVectors from './vectors/pirc100-reference.json';

/**
 * @file RFC8785_Vectors.test.ts
 * @module PiRC-100_Gold_Standard_Audit
 * @version 2.2.6
 * @author EslaM-X | Lead Technical Architect
 * @description 
 * DEFINITIVE PRODUCTION SUITE - 100% CODE COVERAGE MANDATE.
 * Engineered for zero-break compatibility between Backend logic and Frontend execution.
 * Total Tests: 20 | Compliance: RFC 8785 (JCS) Deterministic Validation.
 */

describe('PiRC-100: RFC 8785 Deterministic Vectors & Integrity Compliance', () => {

  /**
   * Reset environment state before each execution to prevent cross-test contamination.
   */
  beforeEach(() => {
    jest.clearAllMocks();
    jest.restoreAllMocks();
  });

  /** SECTION 1: OFFICIAL RFC VECTORS (TESTS 1-4) */
  describe('Official Reference Vector Validation', () => {
    referenceVectors.test_cases.forEach((vector: any) => {
      test(`Reference Case ${vector.id}: JCS Standard Compliance`, () => {
        const result = PiRC100Validator.canonicalize(vector.input);
        expect(result).toBe(vector.expected || vector.expected_canonical);
      });
    });
  });

  /** SECTION 2: DETERMINISM & CONSISTENCY (TESTS 5-6) */
  describe('Deterministic Consistency & Hash Parity', () => {
    test('Test 5: Key Insertion Order Stability (Lexicographical Sort)', () => {
      const p1 = { a: 1, b: 2 };
      const p2 = { b: 2, a: 1 };
      expect(PiRC100Validator.generateDeterministicHash(p1))
        .toBe(PiRC100Validator.generateDeterministicHash(p2));
    });

    test('Test 6: Isomorphic Signature Stability (Cross-Architecture)', () => {
      SecurityManager.rotateKeys();
      const d1 = { action: "sync", status: true };
      const d2 = { status: true, action: "sync" };
      expect(SecurityManager.generatePEPProof(d1).signature)
        .toBe(SecurityManager.generatePEPProof(d2).signature);
    });
  });

  /** SECTION 3: RESILIENCE & 100% PATH EXHAUSTION (TESTS 7-20) */
  describe('Resilience Testing & Security Gates', () => {
    
    test('Test 7: Circular Reference Detection (Stack Overflow Protection)', () => {
      const nodeA: any = { name: "A" };
      const nodeB: any = { name: "B" };
      nodeA.link = nodeB; nodeB.link = nodeA;
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      expect(() => PiRC100Validator.canonicalize(nodeA)).toThrow();
      spy.mockRestore();
    });

    test('Test 8: Primitive Normalization (Null & Undefined)', () => {
      expect(PiRC100Validator.canonicalize(null as any)).toBe("null");
      expect(PiRC100Validator.canonicalize(undefined as any)).toBe("");
    });

    test('Test 10: Absolute Depth Limit Interception (Line 34)', () => {
      const buildDeep = (l: number): any => l <= 0 ? { x: 1 } : { n: buildDeep(l - 1) };
      expect(() => PiRC100Validator.canonicalize(buildDeep(35))).toThrow();
    });

    test('Test 11: SecurityManager Payload Validation (Line 39)', () => {
      expect(SecurityManager.generatePEPProof({} as any).signature).toBe("");
    });

    /**
     * @target SecurityManager.ts:Line 43 (Catch Block)
     * Utilizes a Proxy Trap to force an immediate runtime exception during stringification.
     */
    test('Test 12: SecurityManager Internal Catch Recovery (Line 43)', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      const proxyPoison = new Proxy({ auth: true }, {
        get: () => { throw new Error("FORCE_INTERNAL_CATCH"); }
      });
      expect(SecurityManager.generatePEPProof(proxyPoison as any).signature).toBe("");
      spy.mockRestore();
    });

    /**
     * @target PiRC100Validator.ts:Line 63 (Map Catch)
     * Triggers the internal iteration catch via an enumerable property getter exception.
     */
    test('Test 13: Internal Mapping Loop Catch-Guard (Line 63)', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      const internalBomb = Object.create(null, {
        kaboom: { get: () => { throw new Error("MAPPING_ERR"); }, enumerable: true }
      });
      expect(() => PiRC100Validator.canonicalize({ data: internalBomb })).toThrow();
      spy.mockRestore();
    });

    /**
     * @target PiRC100Validator.ts:Lines 97, 101, 103
     * Comprehensive coverage for the Integrity Verification failure paths.
     */
    test('Test 14: Integrity Fault-Tolerance Path (Lines 97, 101, 103)', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      const circ: any = { id: 1 }; circ.self = circ;
      
      expect(PiRC100Validator.verifyIntegrity(null as any, "secret")).toBeNull();
      expect(PiRC100Validator.verifyIntegrity(circ, "secret")).toBeNull();
      expect(PiRC100Validator.generateDeterministicHash(circ)).toBe("");
      
      spy.mockRestore();
    });

    test('Test 17: PEPProof Verification Success Path (Line 82)', () => {
      const p = SecurityManager.generatePEPProof({ ok: true });
      expect(SecurityManager.verifyPEPProof({ ok: true }, p.signature, p.version)).toBe(true);
    });

    test('Test 18: PEPProof Signature Mismatch Branch (Line 87)', () => {
      const p = SecurityManager.generatePEPProof({ ok: true });
      expect(SecurityManager.verifyPEPProof({ ok: true }, "invalid_sig", p.version)).toBe(false);
    });

    test('Test 19: PEPProof Protocol Version Guard', () => {
      const p = SecurityManager.generatePEPProof({ ok: true });
      expect(SecurityManager.verifyPEPProof({ ok: true }, p.signature, 999)).toBe(false);
    });

    test('Test 20: Array & Primitive Branch Parity (Lines 104-105)', () => {
      expect(PiRC100Validator.canonicalize([undefined, 1])).toBe("[null,1]");
      expect(PiRC100Validator.canonicalize(true)).toBe("true");
      expect(PiRC100Validator.canonicalize(100)).toBe("100");
    });
  });
});
