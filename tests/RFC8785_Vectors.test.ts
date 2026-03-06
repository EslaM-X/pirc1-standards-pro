import { PiRC100Validator } from '../src/core/PiRC100Validator';
import { SecurityManager } from '../src/SecurityManager';
import referenceVectors from './vectors/pirc100-reference.json';

/**
 * @file RFC8785_Vectors.test.ts
 * @module PiRC-100_Gold_Standard_Audit
 * @version 3.0.0
 * @author EslaM-X | Lead Technical Architect
 * @description 
 * FINAL AUDIT-GRADE SUITE. 
 * Targets precisely: SM Line 63 | Validator Lines 89, 126, 132.
 * Strictly maintains API compatibility to ensure Frontend stability.
 * Incorporates peer-review feedback for structural integrity and observability.
 */

describe('PiRC-100: Comprehensive Audit & 100% Coverage Suite', () => {

  beforeEach(() => {
    // Ensuring state purity and resetting diagnostic hooks
    jest.clearAllMocks();
    jest.restoreAllMocks();
    (PiRC100Validator as any).setFaultInjection(false);
    (SecurityManager as any).setFaultInjection(false);
  });

  /** * SECTION 1: RFC 8785 OFFICIAL JCS VECTORS
   * Correctly nested to ensure Jest determinism as per peer review.
   */
  describe('Official JCS Reference Vectors', () => {
    referenceVectors.test_cases.forEach((vector: any) => {
      test(`Vector ${vector.id}: ${vector.description || 'Standard Compliance'}`, () => {
        const result = PiRC100Validator.canonicalize(vector.input);
        expect(result).toBe(vector.expected || vector.expected_canonical);
      });
    });
  });

  /** * SECTION 2: SECURITY MANAGER HARDENING
   * Targets SM Line 63 (Rotation Log) and Fault Recovery.
   */
  describe('SecurityManager: Integrity & Observability', () => {
    
    test('Target SM Line 63: Lazy Rotation & Key Initialization', () => {
      const logSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
      
      // Force internal state reset to trigger lazy rotation logic (Line 63)
      (SecurityManager as any).currentKey = "";
      (SecurityManager as any).keyVersion = 0;
      
      const proof = SecurityManager.generatePEPProof({ op: "audit_init" });
      
      expect(proof.signature).not.toBe("");
      expect((SecurityManager as any).keyVersion).toBeGreaterThan(0);
      expect(logSpy).toHaveBeenCalled(); // Observability check
      
      logSpy.mockRestore();
    });

    test('SecurityManager: Exception Path Coverage', () => {
      const errSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
      (SecurityManager as any).setFaultInjection(true);
      
      const result = SecurityManager.generatePEPProof({ data: "fail" });
      expect(result.signature).toBe("");
      expect(errSpy).toHaveBeenCalled(); 
      
      (SecurityManager as any).setFaultInjection(false);
      errSpy.mockRestore();
    });
  });

  /** * SECTION 3: VALIDATOR RESILIENCE & FAULT EXHAUSTION
   * Targets PiRC100Validator Lines 89, 126, 132 and recursion guards.
   */
  describe('PiRC100Validator: Resilience & Catch Block Exhaustion', () => {

    test('Target VAL Lines 89, 126, 132: Global Catch Blocks', () => {
      const errSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
      (PiRC100Validator as any).setFaultInjection(true);
      
      // Line 89: Canonicalize exception
      expect(() => PiRC100Validator.canonicalize({ x: 1 })).toThrow();
      
      // Line 126: Hash generation exception
      expect(PiRC100Validator.generateDeterministicHash({ x: 1 })).toBe("");
      
      // Line 132: Integrity verification exception
      expect(PiRC100Validator.verifyIntegrity({ x: 1 }, "key")).toBeNull();
      
      expect(errSpy).toHaveBeenCalled();
      (PiRC100Validator as any).setFaultInjection(false);
      errSpy.mockRestore();
    });

    test('Boundary Protection: Depth & Circularity', () => {
      // Line 57: MAX_DEPTH guard
      const createDeep = (n: number): any => n <= 0 ? {l:1} : {b: createDeep(n-1)};
      expect(() => PiRC100Validator.canonicalize(createDeep(35))).toThrow("MAX_DEPTH_REACHED");

      // Circular Reference Protection
      const circ: any = {}; circ.a = circ;
      const errSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
      expect(() => PiRC100Validator.canonicalize(circ)).toThrow();
      errSpy.mockRestore();
    });

    test('Data Normalization: RFC Consistency', () => {
      expect(PiRC100Validator.canonicalize(null as any)).toBe("null");
      expect(PiRC100Validator.canonicalize(undefined as any)).toBe("");
      expect(PiRC100Validator.canonicalize([undefined, 1])).toBe("[null,1]");
    });
  });
});
