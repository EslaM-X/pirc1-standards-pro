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
 * Targets uncovered lines: SecurityManager [43] and Validator [63].
 * @author EslaM-X | Lead Technical Architect
 * @version 2.6.2
 */

describe('PiRC-100: RFC 8785 Deterministic Vectors & Integrity Compliance', () => {

  describe('Official Reference Vector Validation', () => {
    referenceVectors.test_cases.forEach((vector) => {
      test(`Reference Case ${vector.id}: Should match JCS canonical output`, () => {
        const result = PiRC100Validator.canonicalize(vector.input);
        expect(result).toBe(vector.expected_canonical);
      });
    });
  });

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
     * @target Coverage: SecurityManager Line 39 & 43
     * Forces the catch block by inducing a runtime crash during property access.
     */
    test('Gate 3: SecurityManager Internal Error Coverage', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      
      // Target Line 39: Validation fail
      expect(SecurityManager.generatePEPProof({}).signature).toBe("");

      // Target Line 43: Catch Block
      // Trap: Throw on any property access during JCS mapping
      const trappedObj = new Proxy({ a: 1 }, {
        get() { throw new Error("INTERNAL_AUDIT_FAIL"); }
      });
      expect(SecurityManager.generatePEPProof(trappedObj).signature).toBe("");
      
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

    test('Gate 7: Integrity Verification Return Parity', () => {
      const payload = { pirc: 100 };
      expect(typeof PiRC100Validator.verifyIntegrity(payload, "secret")).toBe('string');
      expect(PiRC100Validator.verifyIntegrity(null as any, "secret")).toBeNull();
    });

    /**
     * @gate Gate 8: Absolute Logical Path Exhaustion
     * @description Surgical targeting of Validator Line 63.
     */
    test('Gate 8: Validator Line 63 Mapping Failure Coverage', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      
      // Target: Validator Depth Violation (Line 50)
      const buildDeep = (l: number): any => (l <= 0 ? { e: 1 } : { n: buildDeep(l - 1) });
      expect(() => PiRC100Validator.canonicalize(buildDeep(35))).toThrow("MAX_DEPTH_REACHED");

      // Target: Validator Sub-Structure Mapping Catch (Line 63)
      // Trap: Throw specifically during key iteration/mapping
      const fault = new Proxy({ x: 1 }, {
        ownKeys() { throw new Error("ITERATION_FAIL"); }
      });
      const failPayload = { data: fault };
      expect(() => PiRC100Validator.canonicalize(failPayload)).toThrow();

      // Target: Validator Integrity Catch Block (Line 103)
      const circ: any = { id: "audit-trigger" };
      circ.self = circ; 
      expect(PiRC100Validator.verifyIntegrity(circ, "secret")).toBeNull();
      expect(PiRC100Validator.generateDeterministicHash(circ)).toBe("");

      // Target: JCS Array Undefined Path
      expect(PiRC100Validator.canonicalize([undefined])).toBe("[null]");
      
      spy.mockRestore();
    });
  });
});
