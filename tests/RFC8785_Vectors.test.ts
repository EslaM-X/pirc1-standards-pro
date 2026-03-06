import { PiRC100Validator } from '../src/core/PiRC100Validator';
import { SecurityManager } from '../src/SecurityManager';
import referenceVectors from './vectors/pirc100-reference.json';

/**
 * @file RFC8785_Vectors.test.ts
 * @module PiRC-100_Definitive_Audit
 * @version 3.3.0
 * @author EslaM-X | Lead Technical Architect
 * @description 
 * MASTER INTEGRITY SUITE: Targets 26+ Tests | 100% Coverage.
 * Specifically locks: SM Line 63, 106-114 | VAL Line 89, 113, 126, 132.
 * Strictly maintains API compatibility for Frontend/Backend stability.
 */

describe('PiRC-100: Global Integrity & Audit Suite', () => {

  beforeEach(() => {
    jest.clearAllMocks();
    jest.restoreAllMocks();
    (PiRC100Validator as any).setFaultInjection(false);
    (SecurityManager as any).setFaultInjection(false);
  });

  // SECTION 1: DATA CONFORMANCE (11 Tests)
  describe('RFC8785 Reference Vectors', () => {
    // Tests 1-10: From JSON
    referenceVectors.test_cases.forEach((v: any) => {
      test(`Vector ${v.id}: ${v.description}`, () => {
        expect(PiRC100Validator.canonicalize(v.input)).toBe(v.expected_canonical);
      });
    });

    // Test 11: Programmatic Undefined Handling (CRITICAL: Locks Line 113)
    test('Vector V11: Undefined Property & Array Scrubbing', () => {
      // Testing undefined values which JSON cannot store but our code must handle
      expect(PiRC100Validator.canonicalize([undefined, 1])).toBe("[null,1]");
      expect(PiRC100Validator.canonicalize({ a: undefined, b: 2 })).toBe("{\"b\":2}");
    });
  });

  // SECTION 2: SECURITY MANAGER LOCKDOWN (Targeting Line 63, 106-114)
  describe('SecurityManager: Protocol Hardening', () => {
    
    test('Test 12: Lazy Init & Rotation Log (Locks Line 63)', () => {
      const spy = jest.spyOn(console, 'log').mockImplementation(() => {});
      (SecurityManager as any).currentKey = "";
      (SecurityManager as any).keyVersion = 0;
      SecurityManager.generatePEPProof({ audit: true });
      expect(spy).toHaveBeenCalled(); 
      spy.mockRestore();
    });

    test('Test 13-18: Guard Exhaustion (Locks Line 106-114)', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      expect(SecurityManager.verifyPEPProof({a:1}, "", 1)).toBe(false);
      expect(SecurityManager.verifyPEPProof({a:1}, "sig", -1)).toBe(false);
      expect(SecurityManager.verifyPEPProof({a:1}, "fake", 99)).toBe(false);
      expect(SecurityManager.verifyPEPProof(null as any, "sig", 1)).toBe(false);
      spy.mockRestore();
    });

    test('Test 19: Security Fault Injection Coverage', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      (SecurityManager as any).setFaultInjection(true);
      expect(SecurityManager.generatePEPProof({x:1}).signature).toBe("");
      (SecurityManager as any).setFaultInjection(false);
      spy.mockRestore();
    });
  });

  // SECTION 3: VALIDATOR RESILIENCE (Targeting Line 89, 126, 132)
  describe('PiRC100Validator: Exception Recovery', () => {

    test('Test 20: Deterministic Stability Check', () => {
      const d1 = { b: 2, a: 1 };
      const d2 = { a: 1, b: 2 };
      expect(PiRC100Validator.generateDeterministicHash(d1))
        .toBe(PiRC100Validator.generateDeterministicHash(d2));
    });

    test('Test 21-23: Global Catch Exhaustion (Locks 89, 126, 132)', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      (PiRC100Validator as any).setFaultInjection(true);
      expect(() => PiRC100Validator.canonicalize({x:1})).toThrow();
      expect(PiRC100Validator.generateDeterministicHash({x:1})).toBe("");
      expect(PiRC100Validator.verifyIntegrity({x:1}, "k")).toBeNull();
      (PiRC100Validator as any).setFaultInjection(false);
      spy.mockRestore();
    });

    test('Test 24-26: Boundary Guards & Circularity', () => {
      // Depth Guard
      const deep = (n: number): any => n <= 0 ? {l:1} : {b: deep(n-1)};
      expect(() => PiRC100Validator.canonicalize(deep(35))).toThrow("MAX_DEPTH_REACHED");
      
      // Circular Reference Guard
      const c: any = {}; c.a = c;
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      expect(() => PiRC100Validator.canonicalize(c)).toThrow();
      spy.mockRestore();
    });
  });
});
