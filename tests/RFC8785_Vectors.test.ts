import { PiRC100Validator } from '../src/core/PiRC100Validator';
import { SecurityManager } from '../src/SecurityManager';
/** @notice Cross-implementation parity ensured via Official RFC 8785 Reference Vectors */
import referenceVectors from './vectors/pirc100-reference.json';

/**
 * @file RFC8785_Vectors.test.ts
 * @module PiRC100-Integrity-Suite
 * @description 
 * Finalized Test Suite for PiRC-100 Deterministic Serialization.
 * Engineered for 100% Audit Path Exhaustion (Stmt/Branch/Line).
 * Targets Validator lines [54, 67, 91, 107] and SecurityManager line [39].
 * @author EslaM-X | Lead Technical Architect
 * @version 2.4.0
 */

describe('PiRC-100: RFC 8785 Deterministic Vectors & Integrity Compliance', () => {

  /**
   * @section Official Protocol Reference Vectors
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
   * @section Core Determinism & Hash Parity
   */
  describe('Deterministic Consistency & Signature Parity', () => {
    test('Vector 1: Key Insertion Order Parity', () => {
      const p1 = { a: 1, b: 2 };
      const p2 = { b: 2, a: 1 };
      expect(PiRC100Validator.generateDeterministicHash(p1))
        .toBe(PiRC100Validator.generateDeterministicHash(p2));
    });

    test('Vector 2: SecurityManager Isomorphic Signature Parity', () => {
      SecurityManager.rotateKeys();
      const d1 = { action: "login", status: true };
      const d2 = { status: true, action: "login" };
      expect(SecurityManager.generatePEPProof(d1).signature)
        .toBe(SecurityManager.generatePEPProof(d2).signature);
    });
  });

  /**
   * @section Protocol Resilience & Security Gate Hardening
   */
  describe('Resilience Testing & Security Gates', () => {
    
    test('Gate 1: Null and Undefined Protocol Handling', () => {
      expect(PiRC100Validator.canonicalize(null as any)).toBe("null"); 
      expect(PiRC100Validator.canonicalize(undefined as any)).toBe("");
    });

    test('Gate 2: Indirect Circular Reference Interception', () => {
      const nodeA: any = { name: "NodeA" };
      const nodeB: any = { name: "NodeB" };
      nodeA.link = nodeB;
      nodeB.link = nodeA; 
      
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      expect(() => PiRC100Validator.canonicalize(nodeA)).toThrow("CIRCULAR_REFERENCE_DETECTED"); 
      spy.mockRestore();
    });

    /**
     * @target Coverage: SecurityManager Line 39
     */
    test('Gate 3: SecurityManager Empty/Invalid Payload Rejection', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      // Triggers line 39 in SecurityManager
      expect(SecurityManager.generatePEPProof({} as any).signature).toBe("");
      expect(SecurityManager.generatePEPProof(null as any).signature).toBe("");
      spy.mockRestore();
    });

    test('Gate 4: verifyPEPProof Logic Coverage', () => {
      SecurityManager.rotateKeys();
      const payload = { auth: "valid" };
      const proof = SecurityManager.generatePEPProof(payload);
      expect(SecurityManager.verifyPEPProof(payload, proof.signature, proof.version)).toBe(true);
      expect(SecurityManager.verifyPEPProof(payload, "", proof.version)).toBe(false);
      expect(SecurityManager.verifyPEPProof(payload, proof.signature, 0)).toBe(false);
    });

    test('Gate 7: Integrity Verification Return Parity (string | null)', () => {
      const payload = { pirc: 100 };
      expect(typeof PiRC100Validator.verifyIntegrity(payload, "secret")).toBe('string');
      expect(PiRC100Validator.verifyIntegrity(null as any, "secret")).toBeNull();
    });

    /**
     * @gate Gate 8: Absolute Logical Path Exhaustion
     * @description Direct targeting of uncovered lines 54, 67, 91, 107.
     */
    test('Gate 8: Absolute Logical Path Exhaustion for 100% Audit Compliance', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      
      // 1. Target: Validator Depth Violation (Line 54)
      const buildDeep = (l: number): any => (l <= 0 ? { e: 1 } : { n: buildDeep(l - 1) });
      expect(() => PiRC100Validator.canonicalize(buildDeep(35))).toThrow("MAX_DEPTH_REACHED");

      // 2. Target: Validator Sub-Structure Failure (Line 67)
      // Force failure during key mapping to trigger Line 67 catch
      const failObj = { a: { get b() { throw new Error("INTERNAL_FAIL"); } } };
      expect(() => PiRC100Validator.canonicalize(failObj)).toThrow();

      // 3. Target: Validator Catch Blocks (Lines 91, 107)
      const circ: any = { id: "audit-trigger" };
      circ.self = circ; 
      expect(PiRC100Validator.generateDeterministicHash(circ)).toBe(""); 
      expect(PiRC100Validator.verifyIntegrity(circ, "secret")).toBeNull();

      // 4. Target: JCS Array Serialization (Line 75)
      expect(PiRC100Validator.canonicalize([undefined])).toBe("[null]");
      expect(PiRC100Validator.canonicalize(100)).toBe("100");
      
      spy.mockRestore();
    });
  });
});
