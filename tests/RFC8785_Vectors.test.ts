import { PiRC100Validator } from '../src/core/PiRC100Validator';
import { SecurityManager } from '../src/SecurityManager';
/** @notice Cross-implementation parity ensured via Official RFC 8785 Reference Vectors */
import referenceVectors from './vectors/pirc100-reference.json';

/**
 * @file RFC8785_Vectors.test.ts
 * @module PiRC100-Integrity-Suite
 * @description 
 * Comprehensive Test Suite for PiRC-100 Deterministic Serialization.
 * Engineered for 100% Audit Coverage (Stmt/Branch/Line) while maintaining 
 * strict Frontend-Backend API parity.
 * @author EslaM-X | Lead Technical Architect
 * @version 2.3.7
 */

describe('PiRC-100: RFC 8785 Deterministic Vectors & Integrity Compliance', () => {

  /**
   * @section Official JCS Reference Vectors
   * @description Validates core canonicalization against official RFC 8785 test cases.
   */
  describe('Official Reference Vector Validation', () => {
    referenceVectors.test_cases.forEach((vector) => {
      test(`Reference Case ${vector.id}: Should match JCS canonical output`, () => {
        const result = PiRC100Validator.canonicalize(vector.input);
        expect(result).toBe(vector.expected_canonical);
      });
    });
  });

  /**
   * @section Cryptographic Determinism & Hash Parity
   * @description Ensures that isomorphic payloads yield identical signatures and hashes.
   */
  describe('Deterministic Consistency & Hash Parity', () => {
    test('Vector 1: Object Key Lexicographical Sorting', () => {
      const payloadAlpha = { alpha: 1, beta: 2, gamma: 3 };
      const payloadBeta = { gamma: 3, alpha: 1, beta: 2 };
      expect(PiRC100Validator.generateDeterministicHash(payloadAlpha))
        .toBe(PiRC100Validator.generateDeterministicHash(payloadBeta));
    });

    test('Vector 2: SecurityManager Signature Parity for Reordered Keys', () => {
      SecurityManager.rotateKeys();
      const data1 = { method: "authorize", params: { id: 100, active: true } };
      const data2 = { params: { active: true, id: 100 }, method: "authorize" };
      
      const proof1 = SecurityManager.generatePEPProof(data1);
      const proof2 = SecurityManager.generatePEPProof(data2);
      
      expect(proof1.signature).toBe(proof2.signature);
      expect(proof1.signature).not.toBe("");
    });
  });

  /**
   * @section Protocol Resilience & Security Gate Hardening
   * @description Direct targeting of security edge cases and fail-safe mechanisms.
   */
  describe('Resilience Testing & Security Gates', () => {
    
    test('Gate 1: Null and Undefined Type Handling', () => {
      expect(PiRC100Validator.canonicalize(null as any)).toBe("null"); 
      expect(PiRC100Validator.canonicalize(undefined as any)).toBe("");
    });

    /**
     * @target Coverage: WeakSet Circular Reference Detection
     */
    test('Gate 2: Indirect Circular Reference Detection (Audit Priority)', () => {
      const nodeA: any = { id: "A" };
      const nodeB: any = { id: "B" };
      nodeA.ref = nodeB;
      nodeB.ref = nodeA; // Indirect cycle detection via WeakSet
      
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      expect(() => PiRC100Validator.canonicalize(nodeA)).toThrow(); 
      spy.mockRestore();
    });

    /**
     * @target Coverage: SecurityManager Payload Validation Logic
     */
    test('Gate 3: Rejection of Invalid or Empty Payloads', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      
      const emptyResult = SecurityManager.generatePEPProof({} as any);
      expect(emptyResult.signature).toBe("");
      
      const nullResult = SecurityManager.generatePEPProof(null as any);
      expect(nullResult.signature).toBe("");
      
      spy.mockRestore();
    });

    /**
     * @target Coverage: verifyPEPProof Branching Logic (Success/Fail paths)
     */
    test('Gate 4: verifyPEPProof Full Branch Coverage', () => {
      SecurityManager.rotateKeys();
      const payload = { auth: "valid" };
      const proof = SecurityManager.generatePEPProof(payload);
      
      // Success Path
      expect(SecurityManager.verifyPEPProof(payload, proof.signature, proof.version)).toBe(true);
      
      // Fail Paths (Branch Coverage)
      expect(SecurityManager.verifyPEPProof(payload, "", proof.version)).toBe(false);
      expect(SecurityManager.verifyPEPProof(payload, proof.signature, 0)).toBe(false);
    });

    test('Gate 7: Integrity Verification Return Type Parity', () => {
      const validPayload = { status: "ok" };
      expect(typeof PiRC100Validator.verifyIntegrity(validPayload, "secret")).toBe('string');
      expect(PiRC100Validator.verifyIntegrity(null as any, "secret")).toBeNull();
    });

    /**
     * @gate Gate 8: Path Exhaustion for 100% Coverage
     * @description Surgical targeting of remaining uncovered lines in latest reports.
     */
    test('Gate 8: Logical Path Exhaustion (Audit Completion)', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      
      // 1. Coverage: Max Recursion Depth violation (Validator Lines 52-57)
      const generateDeepObj = (depth: number): any => (depth <= 0 ? { leaf: true } : { branch: generateDeepObj(depth - 1) });
      const toxicPayload = generateDeepObj(35); // Exceeds MAX_DEPTH = 32
      expect(() => PiRC100Validator.canonicalize(toxicPayload)).toThrow("MAX_DEPTH_REACHED");

      // 2. Coverage: SecurityManager Protocol Halt via Exception Catching (Lines 76-82)
      const cyclicObj: any = { trigger: "halt" };
      cyclicObj.self = cyclicObj; 
      const haltProof = SecurityManager.generatePEPProof(cyclicObj);
      expect(haltProof.signature).toBe(""); 

      // 3. Coverage: Primitive and Array Serialization Paths (Validator Line 68)
      expect(PiRC100Validator.canonicalize([undefined])).toBe("[null]");
      expect(PiRC100Validator.canonicalize(42)).toBe("42");
      expect(PiRC100Validator.canonicalize(true)).toBe("true");
      
      spy.mockRestore();
    });
  });
});
