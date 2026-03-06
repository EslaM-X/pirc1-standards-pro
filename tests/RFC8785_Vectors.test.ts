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
 * Targets Validator uncovered lines [50, 63, 103] and SecurityManager [39].
 * @author EslaM-X | Lead Technical Architect
 * @version 2.4.9
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
      nodeB.link = nodeA; 
      
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      expect(() => PiRC100Validator.canonicalize(nodeA)).toThrow(); 
      spy.mockRestore();
    });

    /**
     * @target Coverage: SecurityManager Line 39
     * Inducing specific payload rejection paths.
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
     * @gate Gate 8: Absolute Logical Path Exhaustion (The Audit Closer)
     * @description Surgical targeting of remaining uncovered lines 50, 63, and 103.
     */
    test('Gate 8: Absolute Logical Path Exhaustion for 100% Audit Compliance', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      
      // 1. Target: Validator Depth Violation (Line 50)
      const buildDeep = (l: number): any => (l <= 0 ? { e: 1 } : { n: buildDeep(l - 1) });
      expect(() => PiRC100Validator.canonicalize(buildDeep(35))).toThrow("MAX_DEPTH_REACHED");

      // 2. Target: Validator Sub-Structure Failure (Line 63)
      // Using a throwing getter to trigger the catch inside mapping
      const proxyErr = { a: { get b() { throw new Error("INTERNAL_FAIL"); } } };
      expect(() => PiRC100Validator.canonicalize(proxyErr)).toThrow();

      // 3. Target: Validator Catch Block in verifyIntegrity & generateHash (Line 103)
      const circ: any = { id: "audit-trigger" };
      circ.self = circ; 
      expect(PiRC100Validator.verifyIntegrity(circ, "secret")).toBeNull();
      expect(PiRC100Validator.generateDeterministicHash(circ)).toBe("");
      
      // Also triggers SecurityManager catch block by proxy
      expect(SecurityManager.generatePEPProof(circ).signature).toBe(""); 

      // 4. Target: JCS Array Undefined Serialization
      expect(PiRC100Validator.canonicalize([undefined])).toBe("[null]");
      
      spy.mockRestore();
    });
  });
});
