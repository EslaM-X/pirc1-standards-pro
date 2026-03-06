import { PiRC100Validator } from '../src/core/PiRC100Validator';
import { SecurityManager } from '../src/SecurityManager';
import referenceVectors from './vectors/pirc100-reference.json';

/**
 * @file RFC8785_Vectors.test.ts
 * @module PiRC-100_Gold_Standard_Audit
 * @version 2.2.5
 * @author EslaM-X | Lead Technical Architect
 * @description 
 * Comprehensive integrity suite for PiRC-100 Deterministic JSON Canonicalization (RFC 8785).
 * Enforces 100% Path Exhaustion across SecurityManager and PiRC100Validator.
 * Total Test Count: 20 | Compliance Level: Production-Ready (Zero-Break Policy).
 */

describe('PiRC-100: RFC 8785 Deterministic Vectors & Integrity Compliance', () => {

  /**
   * Global lifecycle hook to ensure environment isolation.
   * Prevents state pollution between test cycles.
   */
  beforeEach(() => {
    jest.clearAllMocks();
    jest.restoreAllMocks();
  });

  /** * SECTION 1: OFFICIAL RFC VECTORS (TESTS 1-4)
   * Validates core canonicalization against the industry standard reference set.
   */
  describe('Official Reference Vector Validation', () => {
    referenceVectors.test_cases.forEach((vector: any) => {
      test(`Reference Case ${vector.id}: Standard Compliance Validation`, () => {
        const result = PiRC100Validator.canonicalize(vector.input);
        expect(result).toBe(vector.expected || vector.expected_canonical);
      });
    });
  });

  /** * SECTION 2: DETERMINISM & CONSISTENCY (TESTS 5-6)
   * Ensures that hash outputs remain identical regardless of key insertion order.
   */
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

  /** * SECTION 3: RESILIENCE & EDGE CASES (TESTS 7-20)
   * Stress-testing the protocol against anomalies and malformed data.
   */
  describe('Resilience Testing & Security Gates', () => {
    
    test('Test 7: Circular Reference Detection (Stack Overflow Protection)', () => {
      const nodeA: any = { name: "A" };
      const nodeB: any = { name: "B" };
      nodeA.link = nodeB; nodeB.link = nodeA;
      
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      expect(() => PiRC100Validator.canonicalize(nodeA)).toThrow();
      spy.mockRestore();
    });

    test('Test 8: Null Input Normalization (Primitive Safety)', () => {
      expect(PiRC100Validator.canonicalize(null as any)).toBe("null");
    });

    test('Test 9: Undefined Input Handling (Protocol Resilience)', () => {
      expect(PiRC100Validator.canonicalize(undefined as any)).toBe("");
    });

    test('Test 10: Absolute Depth Limit Interception (Line 34)', () => {
      const buildDeep = (l: number): any => l <= 0 ? { x: 1 } : { n: buildDeep(l - 1) };
      expect(() => PiRC100Validator.canonicalize(buildDeep(35))).toThrow();
    });

    test('Test 11: SecurityManager Empty Payload Rejection (Line 39)', () => {
      expect(SecurityManager.generatePEPProof({} as any).signature).toBe("");
    });

    /**
     * @target SecurityManager.ts:Line 43 (Catch Block)
     * Forces the stringification phase to fail, validating internal error recovery.
     */
    test('Test 12: SecurityManager Internal Catch Recovery (Line 43)', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      const poison = {
        toJSON: () => { throw new Error("INTERNAL_CRYPTO_FAIL"); }
      };
      expect(SecurityManager.generatePEPProof(poison as any).signature).toBe("");
      spy.mockRestore();
    });

    /**
     * @target PiRC100Validator.ts:Line 63 (Map Catch)
     * Triggers the internal iteration catch via a property descriptor trap.
     */
    test('Test 13: Internal Mapping Loop Catch-Guard (Line 63)', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      const internalBomb = Object.create(null, {
        kaboom: { get: () => { throw new Error("MAPPING_EXCEPTION"); }, enumerable: true }
      });
      expect(() => PiRC100Validator.canonicalize({ data: internalBomb })).toThrow();
      spy.mockRestore();
    });

    test('Test 14: Integrity Null-Safety Branch (Line 97)', () => {
      expect(PiRC100Validator.verifyIntegrity(null as any, "secret")).toBeNull();
    });

    test('Test 15: Integrity Circular Catch Branch (Line 101)', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      const circ: any = { id: 1 }; circ.self = circ;
      expect(PiRC100Validator.verifyIntegrity(circ, "secret")).toBeNull();
      spy.mockRestore();
    });

    test('Test 16: Deterministic Hash Fault-Tolerance (Line 103)', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      const circ: any = { id: 1 }; circ.self = circ;
      expect(PiRC100Validator.generateDeterministicHash(circ)).toBe("");
      spy.mockRestore();
    });

    test('Test 17: PEPProof Positive Verification (Line 82)', () => {
      const p = SecurityManager.generatePEPProof({ ok: true });
      expect(SecurityManager.verifyPEPProof({ ok: true }, p.signature, p.version)).toBe(true);
    });

    test('Test 18: PEPProof Signature Integrity Failure (Line 87)', () => {
      const p = SecurityManager.generatePEPProof({ ok: true });
      expect(SecurityManager.verifyPEPProof({ ok: true }, "corrupt_sig", p.version)).toBe(false);
    });

    test('Test 19: PEPProof Protocol Version Mismatch', () => {
      const p = SecurityManager.generatePEPProof({ ok: true });
      expect(SecurityManager.verifyPEPProof({ ok: true }, p.signature, 999)).toBe(false);
    });

    test('Test 20: Array and Primitive Normalization Coverage (Lines 104-105)', () => {
      expect(PiRC100Validator.canonicalize([undefined, 1])).toBe("[null,1]");
      expect(PiRC100Validator.canonicalize(true)).toBe("true");
      expect(PiRC100Validator.canonicalize(100)).toBe("100");
    });
  });
});
