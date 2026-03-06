import { PiRC100Validator } from '../src/core/PiRC100Validator';
import { SecurityManager } from '../src/SecurityManager';
/** @notice RFC 8785 Reference Vectors */
import referenceVectors from './vectors/pirc100-reference.json';

/**
 * @file RFC8785_Vectors.test.ts
 * @module PiRC100_Integrity_Audit
 * @description 
 * FINAL PATH EXHAUSTION SUITE - VERSION 3.0.0
 * Engineered by EslaM-X for 100% Coverage & Core Team Compliance.
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
    
    test('Gate 1: Null, Undefined, and Empty Handling', () => {
      expect(PiRC100Validator.canonicalize(null as any)).toBe("null"); 
      expect(PiRC100Validator.canonicalize(undefined as any)).toBe("");
      expect(PiRC100Validator.canonicalize({})).toBe("{}");
    });

    test('Gate 2: Circular Reference & Depth Interception', () => {
      const nodeA: any = { name: "NodeA" };
      const nodeB: any = { name: "NodeB" };
      nodeA.link = nodeB;
      nodeB.link = nodeA; 
      
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      // Hit Circular Check
      expect(() => PiRC100Validator.canonicalize(nodeA)).toThrow(); 
      // Hit Depth Check (Line 34)
      const deep = (n: number): any => (n <= 0 ? { x: 1 } : { n: deep(n - 1) });
      expect(() => PiRC100Validator.canonicalize(deep(35))).toThrow();
      spy.mockRestore();
    });

    test('Gate 3: SecurityManager Internal Error Coverage', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      
      // Hit Line 39: Empty Check
      expect(SecurityManager.generatePEPProof({} as any).signature).toBe("");

      // Hit Line 43: Catch Block (Internal Cryptographic Halt)
      const poison = Object.defineProperty({}, 'trigger', {
        get: () => { throw new Error("INTERNAL_FAIL"); },
        enumerable: true
      });
      expect(SecurityManager.generatePEPProof(poison).signature).toBe("");

      // Hit Line 82: verifyPEPProof Fast-Fail
      expect(SecurityManager.verifyPEPProof({a:1}, "", 0)).toBe(false);
      
      spy.mockRestore();
    });

    test('Gate 8: Absolute Logical Path Exhaustion', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      
      // Hit Line 63: Map Iteration Catch
      const bomb = Object.defineProperty({}, 'err', {
        get: () => { throw new Error("MAP_FAIL"); },
        enumerable: true
      });
      expect(() => PiRC100Validator.canonicalize({ data: bomb })).toThrow();

      // Hit Line 87, 97, 101: verifyIntegrity Edge Cases
      expect(PiRC100Validator.verifyIntegrity(null as any, "key")).toBeNull();
      const circ: any = { a: 1 }; circ.self = circ;
      expect(PiRC100Validator.verifyIntegrity(circ, "key")).toBeNull();
      
      // Hit Line 103/104: Hash Catch
      expect(PiRC100Validator.generateDeterministicHash(circ)).toBe("");
      
      spy.mockRestore();
    });

    test('Gate 4: verifyPEPProof Logic Pathing', () => {
      SecurityManager.rotateKeys();
      const payload = { auth: "valid" };
      const proof = SecurityManager.generatePEPProof(payload);
      expect(SecurityManager.verifyPEPProof(payload, proof.signature, proof.version)).toBe(true);
      expect(SecurityManager.verifyPEPProof(payload, "wrong", proof.version)).toBe(false);
    });
    
    test('Gate 9: Array Path Coverage', () => {
      expect(PiRC100Validator.canonicalize([undefined, null, 1])).toBe("[null,null,1]");
    });
  });
});
