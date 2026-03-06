import { PiRC100Validator } from '../src/core/PiRC100Validator';
import { SecurityManager } from '../src/SecurityManager';
import referenceVectors from './vectors/pirc100-reference.json';

/**
 * @file RFC8785_Vectors.test.ts
 * @module PiRC-100_Gold_Standard_Audit
 * @version 2.7.5
 * @author EslaM-X | Lead Technical Architect
 * @description 
 * FINAL PRODUCTION AUDIT SUITE - ARCHITECTED FOR 100% GLOBAL COVERAGE.
 * This suite ensures that PiRC100Validator and SecurityManager meet the 
 * highest architectural standards for Pi Network Mainnet.
 * Targets precisely: PiRC100Validator lines (89, 126, 132).
 */

describe('PiRC-100: Comprehensive Audit & 100% Coverage Suite', () => {

  beforeEach(() => {
    // Ensuring state purity before each test execution to prevent side-effects
    jest.clearAllMocks();
    jest.restoreAllMocks();
    (PiRC100Validator as any).setFaultInjection(false);
    (SecurityManager as any).setFaultInjection(false);
  });

  /** * SECTION 1: RFC 8785 OFFICIAL JCS VECTORS
   * Validates canonicalization against industry-standard test cases.
   */
  describe('Official JCS Reference Vectors', () => {
    referenceVectors.test_cases.forEach((vector: any) => {
      test(`Vector ${vector.id}: Standard Compliance`, () => {
        expect(PiRC100Validator.canonicalize(vector.input)).toBe(vector.expected || vector.expected_canonical);
      });
    });
  });

  /** * SECTION 2: DETERMINISM & CRYPTOGRAPHIC PARITY
   */
  describe('Deterministic & Signature Stability', () => {
    test('Test 5: Property Sorting Stability', () => {
      const payloadA = { b: 2, a: 1 };
      const payloadB = { a: 1, b: 2 };
      expect(PiRC100Validator.generateDeterministicHash(payloadA))
        .toBe(PiRC100Validator.generateDeterministicHash(payloadB));
    });

    test('Test 6: PEP Proof Signature Integrity', () => {
      const payload = { status: "active", tier: "gold" };
      const proof = SecurityManager.generatePEPProof(payload);
      expect(proof.signature).toBeDefined();
      expect(SecurityManager.verifyPEPProof(payload, proof.signature, proof.version)).toBe(true);
    });
  });

  /** * SECTION 3: RESILIENCE & EDGE CASE LOGIC
   */
  describe('Resilience & Edge Case Logic', () => {
    test('Test 7: Circular Reference Detection', () => {
      const circularObj: any = {}; circularObj.self = circularObj;
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      expect(() => PiRC100Validator.canonicalize(circularObj)).toThrow();
      spy.mockRestore();
    });

    test('Test 8: Primitive Normalization Protocol', () => {
      expect(PiRC100Validator.canonicalize(null as any)).toBe("null");
      expect(PiRC100Validator.canonicalize(undefined as any)).toBe("");
      expect(PiRC100Validator.canonicalize(42)).toBe("42");
      expect(PiRC100Validator.canonicalize(true)).toBe("true");
    });

    test('Test 10: Array with Undefined Handling', () => {
      expect(PiRC100Validator.canonicalize([undefined, 1])).toBe("[null,1]");
    });

    test('Test 11: SecurityManager Empty/Invalid Payload Guards', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      expect(SecurityManager.generatePEPProof({} as any).signature).toBe("");
      expect(SecurityManager.verifyPEPProof({ a: 1 }, "", 1)).toBe(false);
      expect(SecurityManager.verifyPEPProof({ a: 1 }, "invalid_hash", -1)).toBe(false);
      spy.mockRestore();
    });
  });

  /** * SECTION 4: ARCHITECTURAL FAULT INJECTION (THE 100% CLOSER)
   * This section targets the recovery blocks (catch) that standard tests cannot reach.
   */
  describe('Final Coverage Exhaustion (Targeting Validator Lines 89, 126, 132)', () => {
    
    /**
     * @target PiRC100Validator.ts: Lines 89, 126, 132
     * Exhausts all internal exception recovery paths using high-level fault injection.
     */
    test('Target VAL Lines 89, 126, 132: Global Catch Exhaustion', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      
      // Activating the internal fault hook safely through type casting
      (PiRC100Validator as any).setFaultInjection(true);
      
      // Line 89: General catch in canonicalize
      expect(() => PiRC100Validator.canonicalize({ data: 1 })).toThrow();
      
      // Line 126: Exception path in deterministic hash generation
      expect(PiRC100Validator.generateDeterministicHash({ data: 1 })).toBe("");
      
      // Line 132: Exception path in integrity verification
      expect(PiRC100Validator.verifyIntegrity({ data: 1 }, "secret")).toBeNull();
      
      (PiRC100Validator as any).setFaultInjection(false);
      spy.mockRestore();
    });

    /**
     * @target PiRC100Validator.ts: Line 57
     * Triggers the MAX_DEPTH_REACHED safety guard.
     */
    test('Target VAL Line 57: Recursion Depth Breach', () => {
      const generateDeepObj = (depth: number) => {
        let obj: any = { leaf: true };
        for (let i = 0; i < depth; i++) obj = { branch: obj };
        return obj;
      };
      // Forcing re-entry to trigger Depth Breach
      expect(() => PiRC100Validator.canonicalize(generateDeepObj(35))).toThrow("MAX_DEPTH_REACHED");
    });

    /**
     * @target SecurityManager.ts: Lines 39-43 (Key Rotation & Lazy Init)
     */
    test('Target SM Line 39-43: Forced Lazy Key Rotation', () => {
      (SecurityManager as any).currentKey = ""; // Clearing state to force rotation logic
      const proof = SecurityManager.generatePEPProof({ init: true });
      expect(proof.signature).not.toBe("");
    });
  });
});
