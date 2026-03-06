import { PiRC100Validator } from '../src/core/PiRC100Validator';
import { SecurityManager } from '../src/SecurityManager';
import referenceVectors from './vectors/pirc100-reference.json';

/**
 * @file RFC8785_Vectors.test.ts
 * @module PiRC-100_Gold_Standard_Audit
 * @version 2.8.5
 * @author EslaM-X | Lead Technical Architect
 * @description 
 * FINAL MISSION: 100% COVERAGE RESTORATION.
 * Engineered to lock SecurityManager Line 58 and Validator Lines 89, 126, 132.
 * Strictly maintains existing API compatibility for Frontend/Backend stability.
 */

describe('PiRC-100: Comprehensive Audit & 100% Coverage Suite', () => {

  beforeEach(() => {
    jest.clearAllMocks();
    jest.restoreAllMocks();
    (PiRC100Validator as any).setFaultInjection(false);
    (SecurityManager as any).setFaultInjection(false);
  });

  /** SECTION 1: RFC 8785 OFFICIAL JCS VECTORS */
  describe('Official JCS Reference Vectors', () => {
    referenceVectors.test_cases.forEach((vector: any) => {
      test(`Vector ${vector.id}: Standard Compliance`, () => {
        expect(PiRC100Validator.canonicalize(vector.input)).toBe(vector.expected || vector.expected_canonical);
      });
    });
  });

  /** SECTION 2: DETERMINISM & CRYPTOGRAPHIC STABILITY */
  describe('Deterministic & Signature Stability', () => {
    test('Test 5: Property Sorting Stability', () => {
      expect(PiRC100Validator.generateDeterministicHash({ b: 2, a: 1 }))
        .toBe(PiRC100Validator.generateDeterministicHash({ a: 1, b: 2 }));
    });

    test('Test 6: PEP Proof Signature Integrity', () => {
      const payload = { status: "active", tier: "gold" };
      const proof = SecurityManager.generatePEPProof(payload);
      expect(proof.signature).toBeDefined();
      expect(SecurityManager.verifyPEPProof(payload, proof.signature, proof.version)).toBe(true);
    });
  });

  /** SECTION 3: RESILIENCE & EDGE CASE LOGIC */
  describe('Resilience & Edge Case Logic', () => {
    test('Test 7: Circular Reference Detection', () => {
      const c: any = {}; c.a = c;
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      expect(() => PiRC100Validator.canonicalize(c)).toThrow();
      spy.mockRestore();
    });

    test('Test 8: Primitive Normalization Protocol', () => {
      expect(PiRC100Validator.canonicalize(null as any)).toBe("null");
      expect(PiRC100Validator.canonicalize(undefined as any)).toBe("");
      expect(PiRC100Validator.canonicalize(100)).toBe("100");
      expect(PiRC100Validator.canonicalize(false)).toBe("false");
    });

    test('Test 10: Array with Undefined Handling', () => {
      expect(PiRC100Validator.canonicalize([undefined, 1])).toBe("[null,1]");
    });

    test('Test 11: SecurityManager Verification Guard Exhaustion', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      expect(SecurityManager.verifyPEPProof({ a: 1 }, "", 1)).toBe(false);
      expect(SecurityManager.verifyPEPProof({ a: 1 }, "sig", -1)).toBe(false);
      spy.mockRestore();
    });
  });

  /** SECTION 4: ARCHITECTURAL FAULT INJECTION (THE 100% CLOSER) */
  describe('Architectural Fault Injection (Targeting Lines SM:58 | VAL:89, 126, 132)', () => {
    
    /**
     * @target SecurityManager.ts: Line 58
     * Forces full key rotation logic and log execution.
     */
    test('Target SM Line 58: Forced Key Rotation Coverage', () => {
      const spy = jest.spyOn(console, 'log').mockImplementation(() => {});
      // Resetting internal state to force rotation (Targeting Line 58)
      (SecurityManager as any).currentKey = "";
      (SecurityManager as any).keyVersion = 0;
      
      const proof = SecurityManager.generatePEPProof({ rotate: true });
      expect(proof.signature).not.toBe("");
      expect((SecurityManager as any).keyVersion).toBeGreaterThan(0);
      spy.mockRestore();
    });

    /**
     * @target SecurityManager.ts: Catch Blocks
     */
    test('Target SM Catch Blocks: Forced Protocol Halt', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      (SecurityManager as any).setFaultInjection(true);
      expect(SecurityManager.generatePEPProof({ data: true }).signature).toBe("");
      (SecurityManager as any).setFaultInjection(false);
      spy.mockRestore();
    });

    /**
     * @target PiRC100Validator.ts: Lines 89, 126, 132
     * Exhausts all internal exception recovery paths in the Validator.
     */
    test('Target VAL Lines 89, 126, 132: Global Catch Exhaustion', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      (PiRC100Validator as any).setFaultInjection(true);
      
      // Line 89
      expect(() => PiRC100Validator.canonicalize({ x: 1 })).toThrow();
      // Line 126
      expect(PiRC100Validator.generateDeterministicHash({ x: 1 })).toBe("");
      // Line 132
      expect(PiRC100Validator.verifyIntegrity({ x: 1 }, "key")).toBeNull();
      
      (PiRC100Validator as any).setFaultInjection(false);
      spy.mockRestore();
    });

    /**
     * @target PiRC100Validator.ts: Line 57
     */
    test('Target VAL Line 57: Recursion Depth Breach', () => {
      const deep = (n: number): any => n <= 0 ? {l:1} : {b: deep(n-1)};
      expect(() => PiRC100Validator.canonicalize(deep(35))).toThrow("MAX_DEPTH_REACHED");
    });
  });
});
