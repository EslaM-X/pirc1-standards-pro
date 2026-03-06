import { PiRC100Validator } from '../src/core/PiRC100Validator';
import { SecurityManager } from '../src/SecurityManager';
/** @notice Cross-implementation parity ensured via Official RFC 8785 Reference Vectors */
import referenceVectors from './vectors/pirc100-reference.json';

/**
 * @file RFC8785_Vectors.test.ts
 * @module PiRC100-Integrity-Suite
 * @description 
 * Comprehensive Test Suite for PiRC-100 Deterministic Serialization.
 * Engineered for 100% Audit Path Exhaustion while maintaining API parity.
 * @author EslaM-X | Lead Technical Architect
 * @version 2.3.9
 */

describe('PiRC-100: RFC 8785 Deterministic Vectors & Integrity Compliance', () => {

  /**
   * @section Official Protocol Reference Vectors
   * @description Validates core canonicalization against RFC 8785 reference data.
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
   * @section Core Determinism & Signature Consistency
   */
  describe('Deterministic Consistency & Hash Parity', () => {
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
      nodeB.link = nodeA; // Indirect cycle detection via WeakSet
      
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      expect(() => PiRC100Validator.canonicalize(nodeA)).toThrow(); 
      spy.mockRestore();
    });

    test('Gate 3: SecurityManager Empty/Invalid Payload Rejection', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      // Triggers internal payload validation (SecurityManager Line 39)
      expect(SecurityManager.generatePEPProof({} as any).signature).toBe("");
      expect(SecurityManager.generatePEPProof(null as any).signature).toBe("");
      spy.mockRestore();
    });

    test('Gate 4: verifyPEPProof Logic Coverage', () => {
      SecurityManager.rotateKeys();
      const payload = { auth: "valid" };
      const proof = SecurityManager.generatePEPProof(payload);
      // Valid path
      expect(SecurityManager.verifyPEPProof(payload, proof.signature, proof.version)).toBe(true);
      // Fail paths (Branch coverage)
      expect(SecurityManager.verifyPEPProof(payload, "", proof.version)).toBe(false);
      expect(SecurityManager.verifyPEPProof(payload, proof.signature, 0)).toBe(false);
    });

    test('Gate 7: Integrity Verification Return Parity (string | null)', () => {
      const payload = { pirc: 100 };
      expect(typeof PiRC100Validator.verifyIntegrity(payload, "secret")).toBe('string');
      expect(PiRC100Validator.verifyIntegrity(null as any, "secret")).toBeNull();
    });

    /**
     * @gate Gate 8: Absolute Logical Path Exhaustion (The Audit Closer)
     * @description Surgical targeting of remaining uncovered lines and branches.
     */
    test('Gate 8: Absolute Logical Path Exhaustion for 100% Audit Compliance', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      
      // 1. Target: Validator Depth Violation (Lines 56, 91)
      const buildDeep = (level: number): any => (level <= 0 ? { e: 1 } : { n: buildDeep(level - 1) });
      const deepPayload = buildDeep(35); // Exceeds MAX_DEPTH = 32
      expect(() => PiRC100Validator.canonicalize(deepPayload)).toThrow();

      // 2. Target: SecurityManager Catch Block Coverage (Lines 76-82)
      const circ: any = { id: "audit-trigger" };
      circ.self = circ; 
      const secureFailure = SecurityManager.generatePEPProof(circ);
      expect(secureFailure.signature).toBe(""); 

      // 3. Target: Array undefined serialization path (Line 75)
      // Canonicalizing [undefined] correctly results in "[null]" in JCS context
      expect(PiRC100Validator.canonicalize([undefined])).toBe("[null]");

      // 4. Testing Primitive Types for Full Coverage
      expect(PiRC100Validator.canonicalize(100)).toBe("100");
      expect(PiRC100Validator.canonicalize(false)).toBe("false");
      
      spy.mockRestore();
    });
  });
});
