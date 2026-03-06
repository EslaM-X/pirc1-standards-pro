import { PiRC100Validator } from '../src/core/PiRC100Validator';
import { SecurityManager } from '../src/SecurityManager';
/** @notice RFC 8785 Reference Vectors */
import referenceVectors from './vectors/pirc100-reference.json';

/**
 * @file RFC8785_Vectors.test.ts
 * @module PiRC100_Integrity_Audit
 * @description 
 * FINAL PATH EXHAUSTION SUITE - VERSION 3.1.0
 * Engineered by EslaM-X for 100% Coverage & Core Team Compliance.
 * Targets: SecurityManager.ts:43 and PiRC100Validator.ts:63, 101.
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
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      const nodeA: any = { name: "NodeA" };
      const nodeB: any = { name: "NodeB" };
      nodeA.link = nodeB;
      nodeB.link = nodeA; 
      
      expect(() => PiRC100Validator.canonicalize(nodeA)).toThrow(); 
      const deep = (n: number): any => (n <= 0 ? { x: 1 } : { n: deep(n - 1) });
      expect(() => PiRC100Validator.canonicalize(deep(35))).toThrow();
      spy.mockRestore();
    });

    /**
     * @target SecurityManager.ts:43
     * Bypasses line 39 and hits the line 43 catch block.
     */
    test('Gate 3: SecurityManager Internal Error Coverage', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      
      // Hit Line 39
      expect(SecurityManager.generatePEPProof({} as any).signature).toBe("");

      // Hit Line 43: Catch Block
      // We use defineProperty to bypass Object.keys check but throw during hashing
      const poison = {};
      Object.defineProperty(poison, 'trigger', {
        get: () => { throw new Error("INTERNAL_FAIL"); },
        enumerable: true
      });
      
      expect(SecurityManager.generatePEPProof(poison).signature).toBe("");
      spy.mockRestore();
    });

    /**
     * @target PiRC100Validator.ts:63, 101
     * Comprehensive coverage for mapping and integrity catch blocks.
     */
    test('Gate 8: Absolute Logical Path Exhaustion', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      
      // Hit Line 63: Map Iteration Catch
      const bomb = {};
      Object.defineProperty(bomb, 'err', {
        get: () => { throw new Error("MAP_FAIL"); },
        enumerable: true
      });
      expect(() => PiRC100Validator.canonicalize({ data: bomb })).toThrow();

      // Hit Line 101/103: Integrity Catch
      const circ: any = { a: 1 }; circ.self = circ;
      expect(PiRC100Validator.verifyIntegrity(circ, "key")).toBeNull();
      
      // Hit Hash Catch
      expect(PiRC100Validator.generateDeterministicHash(circ)).toBe("");
      
      spy.mockRestore();
    });

    test('Gate 4: verifyPEPProof Logic Pathing', () => {
      SecurityManager.rotateKeys();
      const payload = { auth: "valid" };
      const proof = SecurityManager.generatePEPProof(payload);
      expect(SecurityManager.verifyPEPProof(payload, proof.signature, proof.version)).toBe(true);
      expect(SecurityManager.verifyPEPProof(payload, "invalid", proof.version)).toBe(false);
      expect(SecurityManager.verifyPEPProof(payload, proof.signature, 999)).toBe(false);
    });
    
    test('Gate 9: Array Path Coverage', () => {
      expect(PiRC100Validator.canonicalize([undefined, null, 1])).toBe("[null,null,1]");
    });
  });
});
