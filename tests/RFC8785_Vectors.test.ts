import { PiRC100Validator } from '../src/core/PiRC100Validator';
import { SecurityManager } from '../src/SecurityManager';
import referenceVectors from './vectors/pirc100-reference.json';

/**
 * @file RFC8785_Vectors.test.ts
 * @module PiRC100_Integrity_Audit
 * @description 
 * FINAL PATH EXHAUSTION SUITE - PRODUCTION READY.
 * Targets precisely: PiRC100Validator.ts:63, 101.
 * Engineered by EslaM-X | Lead Technical Architect
 */

describe('PiRC-100: RFC 8785 Deterministic Vectors & Integrity Compliance', () => {

  describe('Official Reference Vector Validation', () => {
    referenceVectors.test_cases.forEach((vector: any) => {
      test(`Reference Case ${vector.id}`, () => {
        const canonical = PiRC100Validator.canonicalize(vector.input);
        expect(canonical).toBe(vector.expected || vector.expected_canonical);
      });
    });
  });

  describe('Deterministic Consistency & Hash Parity', () => {
    test('Key Insertion Order Parity', () => {
      const p1 = { a: 1, b: 2 };
      const p2 = { b: 2, a: 1 };
      expect(PiRC100Validator.generateDeterministicHash(p1))
        .toBe(PiRC100Validator.generateDeterministicHash(p2));
    });
  });

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

      // Line 39: Empty Payload
      expect(SecurityManager.generatePEPProof({} as any).signature).toBe("");

      // FIXED: The previous toJSON didn't trigger the catch. 
      // We use a throwing getter which is more reliable in JS environments.
      const fatalGetter = Object.create(null, {
        trigger: {
          get: () => { throw new Error("INTERNAL_FATAL_SIMULATION"); },
          enumerable: true
        }
      });
      expect(SecurityManager.generatePEPProof(fatalGetter).signature).toBe("");

      spy.mockRestore();
    });

    test('Gate 8: Absolute Path Exhaustion', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});

      // Depth limit test (Line 34)
      const buildDeep = (l: number): any =>
        l <= 0 ? { x: 1 } : { n: buildDeep(l - 1) };
      expect(() => PiRC100Validator.canonicalize(buildDeep(35))).toThrow();

      // Line 63 Mapping Exception - Forced Internal Loop Fail
      const bomb = {};
      Object.defineProperty(bomb, 'kaboom', {
        get: () => { throw new Error("MAPPING_EXCEPTION"); },
        enumerable: true
      });
      // Canonicalize should throw when hitting the enumerable 'bomb'
      expect(() => PiRC100Validator.canonicalize({ data: bomb })).toThrow();

      // Line 101/103 Integrity Catch
      const circ: any = { id: 1 };
      circ.self = circ;
      expect(PiRC100Validator.verifyIntegrity(circ, "secret")).toBeNull();
      expect(PiRC100Validator.generateDeterministicHash(circ)).toBe("");

      // Array normalization
      expect(PiRC100Validator.canonicalize([undefined])).toBe("[null]");

      spy.mockRestore();
    });

    test('Gate 4: verifyPEPProof Logic Coverage', () => {
      SecurityManager.rotateKeys();
      const payload = { auth: "valid" };
      const proof = SecurityManager.generatePEPProof(payload);
      
      expect(SecurityManager.verifyPEPProof(payload, proof.signature, proof.version)).toBe(true);
      expect(SecurityManager.verifyPEPProof(payload, "", proof.version)).toBe(false);
      expect(SecurityManager.verifyPEPProof(payload, proof.signature, 999)).toBe(false);
    });
  });
});
