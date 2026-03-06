import { PiRC100Validator } from '../src/core/PiRC100Validator';
import { SecurityManager } from '../src/SecurityManager';
import referenceVectors from './vectors/pirc100-reference.json';

/**
 * @file RFC8785_Vectors.test.ts
 * @module PiRC100_Integrity_Audit
 * @description 
 * DEFINITIVE PATH EXHAUSTION SUITE - HYBRID AUDIT GRADE.
 * Engineered by EslaM-X for 100% coverage across all security gates.
 * Ensures zero regressions for Frontend/Backend stability.
 * @version 3.3.0
 */

describe('PiRC-100: RFC 8785 Deterministic Vectors & Integrity Compliance', () => {

  /** OFFICIAL VECTOR TESTS */
  describe('Official Reference Vector Validation', () => {
    referenceVectors.test_cases.forEach((vector: any) => {
      test(`Reference Case ${vector.id}`, () => {
        const canonical = PiRC100Validator.canonicalize(vector.input);
        // Supports both 'expected' and 'expected_canonical' keys
        expect(canonical).toBe(vector.expected || vector.expected_canonical);
      });
    });
  });

  /** HASH DETERMINISM */
  describe('Deterministic Consistency & Hash Parity', () => {
    test('Key Insertion Order Parity', () => {
      const p1 = { a: 1, b: 2 };
      const p2 = { b: 2, a: 1 };
      const h1 = PiRC100Validator.generateDeterministicHash(p1);
      const h2 = PiRC100Validator.generateDeterministicHash(p2);
      expect(h1).toBe(h2);
    });
  });

  /** RESILIENCE TESTING & SECURITY GATES */
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

    /**
     * @target SecurityManager.ts:43 (Catch Block)
     * Advanced Path Exhaustion via toJSON and Property Descriptors.
     */
    test('Gate 3: SecurityManager Internal Error Coverage', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});

      // Stage 1: Validation Fail-Fast (Line 39)
      expect(SecurityManager.generatePEPProof({} as any).signature).toBe("");

      // Stage 2: Internal Catch via toJSON (Line 43)
      const fatalJSON: any = {
        trigger: true,
        toJSON: () => { throw new Error("INTERNAL_FATAL"); }
      };
      expect(SecurityManager.generatePEPProof(fatalJSON).signature).toBe("");

      // Stage 3: Internal Catch via Getter Simulation (Line 43)
      const fatalGetter = Object.create(null, {
        trigger: {
          get: () => { throw new Error("INTERNAL_FATAL_SIMULATION"); },
          enumerable: true
        }
      });
      expect(SecurityManager.generatePEPProof(fatalGetter).signature).toBe("");

      spy.mockRestore();
    });

    /**
     * @target PiRC100Validator.ts:63, 97, 101
     * FULL PATH EXHAUSTION
     */
    test('Gate 8: Absolute Path Exhaustion', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});

      // 1. Depth limit test (Line 34)
      const buildDeep = (l: number): any =>
        l <= 0 ? { x: 1 } : { n: buildDeep(l - 1) };
      expect(() => PiRC100Validator.canonicalize(buildDeep(35))).toThrow();

      // 2. Mapping exception (Line 63)
      const poison = Object.create(null, {
        bomb: {
          get: () => { throw new Error("MAPPING_EXCEPTION"); },
          enumerable: true
        }
      });
      expect(() => PiRC100Validator.canonicalize({ data: poison })).toThrow();

      // 3. Integrity & Circularity Catch (Line 97, 101, 103)
      const circ: any = { id: 1 };
      circ.self = circ;

      expect(PiRC100Validator.verifyIntegrity(null as any, "secret")).toBeNull();
      expect(PiRC100Validator.verifyIntegrity(circ, "secret")).toBeNull();
      expect(PiRC100Validator.generateDeterministicHash(circ)).toBe("");

      // 4. Array Normalization
      expect(PiRC100Validator.canonicalize([undefined])).toBe("[null]");

      spy.mockRestore();
    });

    /**
     * @target SecurityManager.ts:82 (verifyPEPProof branches)
     * Necessary for branch coverage 100%.
     */
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
