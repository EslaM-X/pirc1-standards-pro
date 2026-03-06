import { PiRC100Validator } from '../src/core/PiRC100Validator';
import { SecurityManager } from '../src/SecurityManager';
import referenceVectors from './vectors/pirc100-reference.json';

/**
 * @file RFC8785_Vectors.test.ts
 * @module PiRC-100_Gold_Standard_Audit
 * @version 2.5.4
 * @author EslaM-X | Lead Technical Architect
 * @description 
 * EMERGENCY RECOVERY SUITE - FINAL AUDIT STAGE.
 * Specifically engineered to reclaim 100% code coverage following source-code re-alignment.
 * * Target Coverage Profiles:
 * - SecurityManager: Exception handling and validation guards (Lines 63, 68, 107).
 * - PiRC100Validator: Protocol-level catch blocks and failure recovery (Lines 83, 103, 119).
 */

describe('PiRC-100: Emergency 100% Coverage Recovery & Resilience Suite', () => {

  beforeEach(() => {
    // Resetting mocks and internal fault states to ensure test isolation
    jest.clearAllMocks();
    jest.restoreAllMocks();
    
    // Explicitly disabling fault injection for baseline health checks
    (PiRC100Validator as any).setFaultInjection(false);
    (SecurityManager as any).setFaultInjection(false);
  });

  /**
   * SECTION 1: STANDARDS COMPLIANCE
   * Validates core canonicalization against the RFC 8785 (JCS) immutable reference vectors.
   */
  test('RFC 8785 Reference Vector Compliance', () => {
    referenceVectors.test_cases.forEach((vector: any) => {
      expect(PiRC100Validator.canonicalize(vector.input))
        .toBe(vector.expected || vector.expected_canonical);
    });
  });

  /**
   * SECTION 2: SECURITY MANAGER HARDENING
   * Targets the cryptographic fail-soft mechanisms and logical integrity guards.
   */
  describe('SecurityManager: Critical Path Exhaustion', () => {
    
    test('Simulated Protocol Halt (Catch Block Recovery)', () => {
      // Suppress logs during expected failure simulation
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      
      // Inject fault to trigger catch block in generatePEPProof
      (SecurityManager as any).setFaultInjection(true);
      
      const result = SecurityManager.generatePEPProof({ audit: "recovery_mode" });
      
      // Verify signature fallback to empty string (Security Protocol Safety)
      expect(result.signature).toBe(""); 
      
      (SecurityManager as any).setFaultInjection(false);
      spy.mockRestore();
    });

    test('Verify Integrity Guard: Invalid Version/Signature handling', () => {
      const payload = { test: true };
      // Test 1: Empty signature rejection
      expect(SecurityManager.verifyPEPProof(payload, "", 1)).toBe(false);
      // Test 2: Protocol version mismatch
      expect(SecurityManager.verifyPEPProof(payload, "any_sig", -1)).toBe(false);
    });
  });

  /**
   * SECTION 3: VALIDATOR HARDENING
   * Targets the protocol-level resilience of the RFC 8785 implementation.
   */
  describe('PiRC100Validator: Protocol Resilience & Catch-Block Targets', () => {

    test('Canonicalization Failure Recovery (Global Catch)', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      (PiRC100Validator as any).setFaultInjection(true);
      
      // Verification of exception bubbling and error logging
      expect(() => PiRC100Validator.canonicalize({ data: 1 })).toThrow();
      expect(spy).toHaveBeenCalled();
      
      (PiRC100Validator as any).setFaultInjection(false);
      spy.mockRestore();
    });

    test('Deterministic Hash Exception Shielding', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      (PiRC100Validator as any).setFaultInjection(true);
      
      // Verify safe failure (return empty string) when internal state is compromised
      expect(PiRC100Validator.generateDeterministicHash({ data: 1 })).toBe("");
      
      (PiRC100Validator as any).setFaultInjection(false);
      spy.mockRestore();
    });

    test('Integrity Verification Exception Shielding', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      (PiRC100Validator as any).setFaultInjection(true);
      
      // Verify null return on integrity breach/exception
      expect(PiRC100Validator.verifyIntegrity({ data: 1 }, "secret_key")).toBeNull();
      
      (PiRC100Validator as any).setFaultInjection(false);
      spy.mockRestore();
    });
  });

  /**
   * SECTION 4: EDGE CASE EXHAUSTION
   * Closes final coverage gaps in recursive data structures.
   */
  test('Recursive Structure & Type Normalization Exhaustion', () => {
    // Array undefined handling
    expect(PiRC100Validator.canonicalize([undefined])).toBe("[null]");
    
    // Object property scrubbing
    expect(PiRC100Validator.canonicalize({ ghost: undefined })).toBe("{}");
    
    // Circular reference validation (Re-confirming stack protection)
    const circular: any = {};
    circular.loop = circular;
    
    const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
    expect(() => PiRC100Validator.canonicalize(circular)).toThrow();
    spy.mockRestore();
  });
});
