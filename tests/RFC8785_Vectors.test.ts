import { PiRC100Validator } from '../src/core/PiRC100Validator';
import { SecurityManager } from '../src/SecurityManager';
import referenceVectors from './vectors/pirc100-reference.json';

/**
 * @file RFC8785_Vectors.test.ts
 * @module PiRC-100_Audit_Suite
 * @description Master Audit Suite for 100% Path Exhaustion.
 * Engineered by EslaM-X | Lead Technical Architect.
 */

describe('PiRC-100: RFC 8785 Deterministic Vectors & Integrity Compliance', () => {

  /** 1. OFFICIAL VECTORS - Never Remove */
  describe('Official Reference Vector Validation', () => {
    referenceVectors.test_cases.forEach((vector: any) => {
      test(`Reference Case ${vector.id}`, () => {
        const canonical = PiRC100Validator.canonicalize(vector.input);
        expect(canonical).toBe(vector.expected || vector.expected_canonical);
      });
    });
  });

  /** 2. HASH DETERMINISM */
  describe('Deterministic Consistency & Hash Parity', () => {
    test('Key Insertion Order Parity', () => {
      const p1 = { a: 1, b: 2 };
      const p2 = { b: 2, a: 1 };
      expect(PiRC100Validator.generateDeterministicHash(p1))
        .toBe(PiRC100Validator.generateDeterministicHash(p2));
    });
  });

  /** 3. SECURITY & RESILIENCE - 100% COVERAGE TARGETS */
  describe('Resilience Testing & Security Gates', () => {
    
    test('Gate 1: Circular Reference Detection', () => {
      const nodeA: any = { name: "NodeA" };
      const nodeB: any = { name: "NodeB" };
      nodeA.link = nodeB;
      nodeB.link = nodeA;

      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      expect(() => PiRC100Validator.canonicalize(nodeA)).toThrow();
      spy.mockRestore();
    });

    test('Gate 3: SecurityManager Internal Error Coverage', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      // Hit Line 39
      expect(SecurityManager.generatePEPProof({} as any).signature).toBe("");
      // Hit Line 43: Catch Block
      const poison = Object.create(null, {
        trigger: { get: () => { throw new Error("INTERNAL_FAIL"); }, enumerable: true }
      });
      expect(SecurityManager.generatePEPProof(poison).signature).toBe("");
      spy.mockRestore();
    });

    test('Gate 8: Absolute Path Exhaustion (Validator Focus)', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});

      // [Target: Line 34] Depth Limit
      const buildDeep = (l: number): any => l <= 0 ? { x: 1 } : { n: buildDeep(l - 1) };
      expect(() => PiRC100Validator.canonicalize(buildDeep(35))).toThrow();

      // [Target: Line 63] Mapping Exception Internal Loop
      const bomb = {};
      Object.defineProperty(bomb, 'kaboom', {
        get: () => { throw new Error("MAPPING_FAIL"); },
        enumerable: true
      });
      expect(() => PiRC100Validator.canonicalize({ data: bomb })).toThrow();

      // [Target: Line 97 & 101] Integrity & Hash Catch
      const circ: any = { id: 1 }; circ.self = circ;
      // Hit Null-Safety Branch (Line 97)
      expect(PiRC100Validator.verifyIntegrity(null as any, "secret")).toBeNull();
      // Hit Internal Circular/Catch Branch (Line 101 & 103)
      expect(PiRC100Validator.verifyIntegrity(circ, "secret")).toBeNull();
      expect(PiRC100Validator.generateDeterministicHash(circ)).toBe("");

      // [Target: Line 104/105] Array Logic
      expect(PiRC100Validator.canonicalize([undefined])).toBe("[null]");

      spy.mockRestore();
    });

    test('Gate 4: verifyPEPProof Logic Coverage', () => {
      SecurityManager.rotateKeys();
      const payload = { auth: "valid" };
      const proof = SecurityManager.generatePEPProof(payload);
      
      // Hit Version & Signature Branches
      expect(SecurityManager.verifyPEPProof(payload, proof.signature, proof.version)).toBe(true);
      expect(SecurityManager.verifyPEPProof(payload, "", proof.version)).toBe(false);
      expect(SecurityManager.verifyPEPProof(payload, proof.signature, 999)).toBe(false);
    });
  });
});
