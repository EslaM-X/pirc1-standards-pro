import { PiRC100Validator } from '../src/core/PiRC100Validator';
import { SecurityManager } from '../src/SecurityManager';
/** @notice RFC 8785 Deterministic Vectors */
import referenceVectors from './vectors/pirc100-reference.json';

/**
 * @file RFC8785_Vectors.test.ts
 * @module PiRC100_Integrity_Audit
 * @description 
 * FINAL AUDIT VERSION - ZERO ASSUMPTIONS.
 * Targets precisely: SecurityManager.ts:43 and PiRC100Validator.ts:63.
 * Engineered by EslaM-X to ensure 100% Core Team compliance.
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

    /**
     * @target SecurityManager.ts:43
     * Force internal catch by bypassing empty-check in line 39
     * then exploding during the hashing phase.
     */
    test('Gate 3: SecurityManager Internal Error Coverage', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      
      // Line 39 Coverage
      expect(SecurityManager.generatePEPProof({} as any).signature).toBe("");

      // Line 43 Coverage: The "Proxy Bomb"
      // This object appears to have keys (bypasses line 39), 
      // but throws as soon as the validator tries to read them.
      const toxic = new Proxy({ trigger: true }, {
        get: (t, p) => {
          if (p === 'trigger') throw new Error("PROTOCOL_INTERNAL_HALT");
          return (t as any)[p];
        }
      });
      
      expect(SecurityManager.generatePEPProof(toxic).signature).toBe("");
      spy.mockRestore();
    });

    /**
     * @target PiRC100Validator.ts:63
     * Force the map iteration to fail internally.
     */
    test('Gate 8: Absolute Logical Path Exhaustion', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      
      // Line 34: Depth Limit
      const buildDeep = (l: number): any => (l <= 0 ? { x: 1 } : { n: buildDeep(l - 1) });
      expect(() => PiRC100Validator.canonicalize(buildDeep(35))).toThrow();

      // Line 63: Mapping Catch (Internal Loop Failure)
      // Using Object.create(null) with a throwing enumerable property.
      const bomb = Object.create(null);
      Object.defineProperty(bomb, 'kaboom', {
        get: () => { throw new Error("INTERNAL_MAP_FAILURE"); },
        enumerable: true
      });

      // Wrap it in another object to reach Stage 6 in Validator
      expect(() => PiRC100Validator.canonicalize({ data: bomb })).toThrow();

      // Line 103: Integrity Catch
      const circ: any = { id: 1 }; circ.self = circ; 
      expect(PiRC100Validator.verifyIntegrity(circ, "secret")).toBeNull();
      
      spy.mockRestore();
    });

    test('Gate 4: verifyPEPProof Logic Coverage', () => {
      SecurityManager.rotateKeys();
      const payload = { auth: "valid" };
      const proof = SecurityManager.generatePEPProof(payload);
      expect(SecurityManager.verifyPEPProof(payload, proof.signature, proof.version)).toBe(true);
    });
  });
});
