import { PiRC100Validator } from '../src/core/PiRC100Validator';
import { SecurityManager } from '../src/SecurityManager';
import referenceVectors from './vectors/pirc100-reference.json';

/**
 * @file RFC8785_Vectors.test.ts
 * @module PiRC-100_Integrity_Audit
 * @version 2.5.4
 * @author EslaM-X | Lead Technical Architect
 * @description 
 * EMERGENCY RECOVERY AUDIT SUITE.
 * Purposefully engineered to reclaim 100% code coverage following architectural line-shifts.
 * Targets specific uncovered blocks: 
 * - SecurityManager: Lines 63, 68 (Exception Handling) and 107 (Logic Gates).
 * - PiRC100Validator: Lines 83, 103, 119 (Protocol Halt Recovery).
 * * Strict Zero-Break Policy: Utilizes Fault Injection via 'any' casting to preserve 
 * production-grade encapsulation.
 */

describe('PiRC-100: Emergency 100% Coverage Recovery & Integrity Compliance', () => {

  beforeEach(() => {
    // Reset all mocks to maintain state isolation across test cycles
    jest.clearAllMocks();
    jest.restoreAllMocks();
    
    // Ensure the system under test (SUT) starts in a healthy, production-ready state
    (PiRC100Validator as any).setFaultInjection(false);
    (SecurityManager as any).setFaultInjection(false);
  });

  /**
   * SECTION 1: RFC 8785 (JCS) STANDARD COMPLIANCE
   * Validates the core canonicalization engine against official reference vectors.
   */
  test('Standard Compliance: RFC 8785 Deterministic Vectors', () => {
    referenceVectors.test_cases.forEach((vector: any) => {
      const result = PiRC100Validator.canonicalize(vector.input);
      expect(result).toBe(vector.expected || vector.expected_canonical);
    });
  });

  /**
   * SECTION 2: SECURITY MANAGER HARDENING
   * Targets specific exception paths and logical branches in the cryptographic orchestrator.
   */
  describe('SecurityManager Hardening (Lines 63, 68, 107)', () => {
    /**
     * @target SM Line 63 & 68
     * Validates the Fail-Soft mechanism when an internal cryptographic halt occurs.
     */
    test('Target SM Line 63 & 68: Internal Fault Recovery Path', () => {
      // Suppress console errors for clean audit logs during simulated failure
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      
      (SecurityManager as any).setFaultInjection(true); // Trigger simulated failure
      
      const result = SecurityManager.generatePEPProof({ protocol: "recovery" });
      
      // Verification of the fail-soft empty signature return (Line 68)
      expect(result.signature).toBe(""); 
      
      (SecurityManager as any).setFaultInjection(false);
      spy.mockRestore();
    });

    /**
     * @target SM Line 107
     * Exhausts logical branches for signature verification and version mismatches.
     */
    test('Target SM Line 107: Multi-Branch Verification Guard', () => {
      const payload = { test: true };
      // Test cases for invalid signatures and out-of-sync versions
      expect(SecurityManager.verifyPEPProof(payload, "", 0)).toBe(false);
      expect(SecurityManager.verifyPEPProof(payload, "invalid_hash", -1)).toBe(false);
    });
  });

  /**
   * SECTION 3: VALIDATOR PROTOCOL RESILIENCE
   * Ensures the core validator properly logs and recovers from unexpected execution faults.
   */
  describe('Validator Hardening (Lines 83, 103, 119)', () => {
    /**
     * @target VAL Line 83
     * Validates protocol-level error propagation during canonicalization.
     */
    test('Target VAL Line 83: Canonicalize Protocol Halt Recovery', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      (PiRC100Validator as any).setFaultInjection(true);
      
      expect(() => PiRC100Validator.canonicalize({ data: 1 })).toThrow();
      
      (PiRC100Validator as any).setFaultInjection(false);
      spy.mockRestore();
    });

    /**
     * @target VAL Line 103
     * Validates hashing fallback when the input cannot be canonicalized.
     */
    test('Target VAL Line 103: Deterministic Hash Recovery Path', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      (PiRC100Validator as any).setFaultInjection(true);
      
      const hash = PiRC100Validator.generateDeterministicHash({ data: 1 });
      expect(hash).toBe(""); // Expected result on failure (Line 103)
      
      (PiRC100Validator as any).setFaultInjection(false);
      spy.mockRestore();
    });

    /**
     * @target VAL Line 119
     * Validates HMAC integrity fallback under system stress.
     */
    test('Target VAL Line 119: Integrity Verification Recovery Path', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      (PiRC100Validator as any).setFaultInjection(true);
      
      const hmac = PiRC100Validator.verifyIntegrity({ data: 1 }, "secret_key");
      expect(hmac).toBeNull(); // Expected result on failure (Line 119)
      
      (PiRC100Validator as any).setFaultInjection(false);
      spy.mockRestore();
    });
  });

  /**
   * SECTION 4: EDGE CASE EXHAUSTION
   * Final sweep of edge cases to ensure no functional gaps remain.
   */
  test('Edge Case Exhaustion: Arrays, Undefined, and Circularity', () => {
    // Array Normalization
    expect(PiRC100Validator.canonicalize([undefined])).toBe("[null]");
    
    // Object Property Omission (Standard Behavior)
    expect(PiRC100Validator.canonicalize({ a: undefined })).toBe("{}");
    
    // Circular Reference Protection
    const circular: any = {}; circular.self = circular;
    const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
    expect(() => PiRC100Validator.canonicalize(circular)).toThrow();
    spy.mockRestore();
  });
});
