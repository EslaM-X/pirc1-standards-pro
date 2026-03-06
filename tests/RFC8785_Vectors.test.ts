import { PiRC100Validator } from '../src/core/PiRC100Validator';
import { SecurityManager } from '../src/SecurityManager';
import referenceVectors from './vectors/pirc100-reference.json';

/**
 * @file RFC8785_Vectors.test.ts
 * @module PiRC-100_Final_Audit
 * @description 
 * FINAL PATH EXHAUSTION SUITE - HYBRID VERSION 4.0.
 * Engineered by EslaM-X to reach 100% Total Coverage.
 * Targets: PiRC100Validator.ts:63, 101 + Branch Coverage.
 */

describe('PiRC-100: RFC 8785 Deterministic Vectors & Integrity Compliance', () => {

  /** 1. OFFICIAL REFERENCE VECTORS */
  describe('Official Reference Vector Validation', () => {
    referenceVectors.test_cases.forEach((vector: any) => {
      test(`Reference Case ${vector.id}`, () => {
        const canonical = PiRC100Validator.canonicalize(vector.input);
        expect(canonical).toBe(vector.expected || vector.expected_canonical);
      });
    });
  });

  /** 2. CONSISTENCY & DETERMINISM */
  describe('Deterministic Consistency & Hash Parity', () => {
    test('Vector 1: Key Insertion Order Parity', () => {
      const p1 = { a: 1, b: 2 };
      const p2 = { b: 2, a: 1 };
      expect(PiRC100Validator.generateDeterministicHash(p1))
        .toBe(PiRC100Validator.generateDeterministicHash(p2));
    });

    test('Vector 2: Isomorphic Signature Parity', () => {
      SecurityManager.rotateKeys();
      const d1 = { action: "sync", status: true };
      const d2 = { status: true, action: "sync" };
      expect(SecurityManager.generatePEPProof(d1).signature)
        .toBe(SecurityManager.generatePEPProof(d2).signature);
    });
  });

  /** 3. THE "ALL-IN" RESILIENCE SUITE (100% Coverage Target) */
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
      // Hit Line 39 (Validation)
      expect(SecurityManager.generatePEPProof({} as any).signature).toBe("");
      // Hit Line 43 (Catch Block)
      const poison = Object.create(null, {
        trigger: { get: () => { throw new Error("INTERNAL_FAIL"); }, enumerable: true }
      });
      expect(SecurityManager.generatePEPProof(poison).signature).toBe("");
      spy.mockRestore();
    });

    test('Gate 8: Absolute Path Exhaustion (The 100% Key)', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});

      // [Line 34] Depth Limit
      const buildDeep = (l: number): any => l <= 0 ? { x: 1 } : { n: buildDeep(l - 1) };
      expect(() => PiRC100Validator.canonicalize(buildDeep(35))).toThrow();

      // [Line 63] Mapping Catch (Internal Loop Fail)
      // This is crucial for the 92.68% to become 100%
      const internalBomb = Object.create(null, {
        kaboom: {
          get: () => { throw new Error("MAP_FAIL"); },
          enumerable: true
        }
      });
      expect(() => PiRC100Validator.canonicalize({ data: internalBomb })).toThrow();

      // [Line 101/103] Integrity & Hash Catch
      const circ: any = { id: 1 }; circ.self = circ;
      // Branch 1: Null check
      expect(PiRC100Validator.verifyIntegrity(null as any, "secret")).toBeNull();
      // Branch 2: Internal Circular/Catch
      expect(PiRC100Validator.verifyIntegrity(circ, "secret")).toBeNull();
      expect(PiRC100Validator.generateDeterministicHash(circ)).toBe("");

      // [Stage 6/7] Array logic
      expect(PiRC100Validator.canonicalize([undefined, null, 1])).toBe("[null,null,1]");

      spy.mockRestore();
    });

    test('Gate 4: verifyPEPProof Logic Coverage', () => {
      SecurityManager.rotateKeys();
      const payload = { auth: "valid" };
      const proof = SecurityManager.generatePEPProof(payload);
      // Full branch coverage for Line 82/87
      expect(SecurityManager.verifyPEPProof(payload, proof.signature, proof.version)).toBe(true);
      expect(SecurityManager.verifyPEPProof(payload, "", proof.version)).toBe(false);
      expect(SecurityManager.verifyPEPProof(payload, proof.signature, 999)).toBe(false);
    });

    test('Gate 10: Extra Edge Cases for Branch Parity', () => {
        // Ensuring all conditional branches in Validator are touched
        expect(PiRC100Validator.canonicalize(true)).toBe("true");
        expect(PiRC100Validator.canonicalize(100)).toBe("100");
    });
  });
});
