import { PiRC100Validator } from '../src/core/PiRC100Validator';
import { SecurityManager } from '../src/SecurityManager';
import referenceVectors from './vectors/pirc100-reference.json';

/**
 * @file RFC8785_Vectors.test.ts
 * @module PiRC-100_Gold_Standard_Audit
 * @version 2.9.0
 * @author EslaM-X | Lead Technical Architect
 * @description 
 * FINAL ARCHITECTURAL LOCKDOWN. 
 * Targets precisely: SM Line 63 | Validator Lines 89, 126, 132.
 * Maintains 100% compatibility with Frontend and Backend Logic.
 */

describe('PiRC-100: Comprehensive Audit & 100% Coverage Suite', () => {

  beforeEach(() => {
    jest.clearAllMocks();
    jest.restoreAllMocks();
    (PiRC100Validator as any).setFaultInjection(false);
    (SecurityManager as any).setFaultInjection(false);
  });

  /** SECTION 1: OFFICIAL JCS VECTORS (20+ Tests) */
  describe('Official JCS Reference Vectors', () => {
    referenceVectors.test_cases.forEach((vector: any) => {
      test(`Vector ${vector.id}: Standard Compliance`, () => {
        expect(PiRC100Validator.canonicalize(vector.input)).toBe(vector.expected || vector.expected_canonical);
      });
    });
  });

  /** SECTION 2: SECURITY & CRYPTO LOGIC */
  describe('SecurityManager & Signature Stability', () => {
    test('Test 5: PEP Proof Signature Integrity', () => {
      const payload = { status: "active", tier: "gold" };
      const proof = SecurityManager.generatePEPProof(payload);
      expect(proof.signature).toBeDefined();
      expect(SecurityManager.verifyPEPProof(payload, proof.signature, proof.version)).toBe(true);
    });

    /**
     * @target SecurityManager.ts: Line 63
     * This test forces the rotation logic to trigger the specific uncovered line.
     */
    test('Target SM Line 63: Rotation Log Coverage', () => {
      const spy = jest.spyOn(console, 'log').mockImplementation(() => {});
      (SecurityManager as any).currentKey = "";
      (SecurityManager as any).keyVersion = 0;
      
      const result = SecurityManager.generatePEPProof({ trigger: "full_rotation" });
      expect(result.signature).not.toBe("");
      expect((SecurityManager as any).keyVersion).toBeGreaterThan(0);
      spy.mockRestore();
    });
  });

  /** SECTION 3: VALIDATOR RESILIENCE (100% LOCK) */
  describe('PiRC100Validator Exhaustion (Targeting 89, 126, 132)', () => {
    
    test('Target VAL Lines 89, 126, 132: Global Catch Blocks', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      (PiRC100Validator as any).setFaultInjection(true);
      
      // Line 89: Canonicalize
      expect(() => PiRC100Validator.canonicalize({ x: 1 })).toThrow();
      // Line 126: Hash
      expect(PiRC100Validator.generateDeterministicHash({ x: 1 })).toBe("");
      // Line 132: Integrity
      expect(PiRC100Validator.verifyIntegrity({ x: 1 }, "key")).toBeNull();
      
      (PiRC100Validator as any).setFaultInjection(false);
      spy.mockRestore();
    });

    test('Target VAL Line 57: MAX_DEPTH Guard', () => {
      const deep = (n: number): any => n <= 0 ? {l:1} : {b: deep(n-1)};
      expect(() => PiRC100Validator.canonicalize(deep(35))).toThrow("MAX_DEPTH_REACHED");
    });

    test('Standard Edge Cases', () => {
      expect(PiRC100Validator.canonicalize(null as any)).toBe("null");
      expect(PiRC100Validator.canonicalize(undefined as any)).toBe("");
      const c: any = {}; c.a = c;
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      expect(() => PiRC100Validator.canonicalize(c)).toThrow();
      spy.mockRestore();
    });
  });

  /** SECTION 4: SM FAULT RECOVERY */
  test('Target SM Catch Blocks: Forced Rejection', () => {
    const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
    (SecurityManager as any).setFaultInjection(true);
    expect(SecurityManager.generatePEPProof({ data: true }).signature).toBe("");
    (SecurityManager as any).setFaultInjection(false);
    spy.mockRestore();
  });
});
