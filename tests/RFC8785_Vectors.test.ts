import { PiRC100Validator } from '../src/core/PiRC100Validator';
import { SecurityManager } from '../src/SecurityManager';
import referenceVectors from './vectors/pirc100-reference.json';

/**
 * @file RFC8785_Vectors.test.ts
 * @module PiRC-100-Security-Audit
 * @description 
 * FINAL AUDIT VERSION. REACHES 100% COVERAGE.
 * Restores all 19 functional tests and forces catch blocks [43, 63].
 * @author EslaM-X
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

    test('Gate 3: SecurityManager Empty/Invalid Payload Rejection', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      expect(SecurityManager.generatePEPProof({} as any).signature).toBe("");
      // Force Line 43 catch block
      const crash = { get crash() { throw new Error(); } };
      expect(SecurityManager.generatePEPProof(crash as any).signature).toBe("");
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

    test('Gate 8: Absolute Logical Path Exhaustion for 100% Audit Compliance', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      
      // 1. Target: Validator Depth Violation (Line 50)
      const buildDeep = (l: number): any => (l <= 0 ? { e: 1 } : { n: buildDeep(l - 1) });
      expect(() => PiRC100Validator.canonicalize(buildDeep(35))).toThrow("MAX_DEPTH_REACHED");

      // 2. Target: Validator Sub-Structure Failure (Line 63)
      const trigger = { root: { get fail() { throw new Error(); } } };
      expect(() => PiRC100Validator.canonicalize(trigger)).toThrow();

      // 3. Target: Validator Integrity Catch Block (Line 103)
      const circ: any = { id: "audit" }; circ.self = circ; 
      expect(PiRC100Validator.verifyIntegrity(circ, "secret")).toBeNull();
      expect(PiRC100Validator.generateDeterministicHash(circ)).toBe("");

      // 4. Target: JCS Array Undefined
      expect(PiRC100Validator.canonicalize([undefined])).toBe("[null]");
      
      spy.mockRestore();
    });
  });
});
