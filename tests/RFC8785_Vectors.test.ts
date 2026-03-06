import { PiRC100Validator } from '../src/core/PiRC100Validator';
import { SecurityManager } from '../src/SecurityManager';
import referenceVectors from './vectors/pirc100-reference.json';

/**
 * @file RFC8785_Vectors.test.ts
 * @module PiRC-100_Gold_Standard_Audit
 * @version 2.2.8
 * @author EslaM-X | Lead Technical Architect
 * @description 
 * FINAL AUDIT SUITE - MANDATORY 100% COVERAGE.
 * Target Uncovered Lines: SecurityManager (43), Validator (63, 101).
 * Zero-Break Policy: Strict adherence to existing Backend/Frontend contracts.
 */

describe('PiRC-100: RFC 8785 Deterministic Vectors & Integrity Compliance', () => {

  beforeEach(() => {
    jest.clearAllMocks();
    jest.restoreAllMocks();
  });

  /** SECTION 1: OFFICIAL RFC VECTORS (TESTS 1-4) */
  describe('Official Reference Vector Validation', () => {
    referenceVectors.test_cases.forEach((vector: any) => {
      test(`Reference Case ${vector.id}: Standard Compliance`, () => {
        expect(PiRC100Validator.canonicalize(vector.input)).toBe(vector.expected || vector.expected_canonical);
      });
    });
  });

  /** SECTION 2: DETERMINISM & CONSISTENCY (TESTS 5-6) */
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

  /** SECTION 3: RESILIENCE & 100% COVERAGE TRAPS (TESTS 7-20) */
  describe('Resilience Testing & Security Gates', () => {
    
    test('Test 7: Circular Reference Detection', () => {
      const c: any = {}; c.a = c;
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      expect(() => PiRC100Validator.canonicalize(c)).toThrow();
      spy.mockRestore();
    });

    test('Test 8: Primitive Normalization', () => {
      expect(PiRC100Validator.canonicalize(null as any)).toBe("null");
      expect(PiRC100Validator.canonicalize(undefined as any)).toBe("");
    });

    test('Test 9: Numeric & Boolean Branch Coverage', () => {
      expect(PiRC100Validator.canonicalize(100)).toBe("100");
      expect(PiRC100Validator.canonicalize(false)).toBe("false");
    });

    test('Test 10: Deep Nesting Limit (Line 34)', () => {
      const deep = (n: number): any => n <= 0 ? {x:1} : {n: deep(n-1)};
      expect(() => PiRC100Validator.canonicalize(deep(35))).toThrow();
    });

    test('Test 11: SecurityManager Rejection Path (Line 39)', () => {
      expect(SecurityManager.generatePEPProof({} as any).signature).toBe("");
    });

    /**
     * @target SecurityManager.ts:Line 43 (THE TRAP)
     * Forces immediate catch via Proxy.
     */
    test('Test 12: SecurityManager Internal Catch Recovery (Line 43)', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      const poison = new Proxy({ a: 1 }, {
        get: () => { throw new Error("CRITICAL_HALT"); }
      });
      expect(SecurityManager.generatePEPProof(poison as any).signature).toBe("");
      spy.mockRestore();
    });

    /**
     * @target PiRC100Validator.ts:Line 63 (THE TRAP)
     */
    test('Test 13: Internal Mapping Loop Catch-Guard (Line 63)', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      const bomb = Object.create(null, {
        fail: { get: () => { throw new Error("ITER_FAIL"); }, enumerable: true }
      });
      expect(() => PiRC100Validator.canonicalize({ data: bomb })).toThrow();
      spy.mockRestore();
    });

    test('Test 14: Integrity Null Safety (Line 97)', () => {
      expect(PiRC100Validator.verifyIntegrity(null as any, "k")).toBeNull();
    });

    /**
     * @target PiRC100Validator.ts:Line 101 (THE TRAP)
     */
    test('Test 15: Integrity Circular Catch Branch (Line 101)', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      const circ: any = { x: 1 }; circ.self = circ;
      expect(PiRC100Validator.verifyIntegrity(circ, "k")).toBeNull();
      spy.mockRestore();
    });

    test('Test 16: Deterministic Hash Error Path (Line 103)', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      const circ: any = { x: 1 }; circ.self = circ;
      expect(PiRC100Validator.generateDeterministicHash(circ)).toBe("");
      spy.mockRestore();
    });

    test('Test 17: PEPProof Success Path', () => {
      const p = SecurityManager.generatePEPProof({ ok: true });
      expect(SecurityManager.verifyPEPProof({ ok: true }, p.signature, p.version)).toBe(true);
    });

    test('Test 18: PEPProof Sig Failure', () => {
      expect(SecurityManager.verifyPEPProof({ ok: true }, "bad", 1)).toBe(false);
    });

    test('Test 19: PEPProof Version Mismatch', () => {
      expect(SecurityManager.verifyPEPProof({ ok: true }, "sig", 999)).toBe(false);
    });

    test('Test 20: Array & Literal Coverage', () => {
      expect(PiRC100Validator.canonicalize([undefined, 1])).toBe("[null,1]");
      expect(PiRC100Validator.canonicalize("string")).toBe("\"string\"");
    });
  });
});
