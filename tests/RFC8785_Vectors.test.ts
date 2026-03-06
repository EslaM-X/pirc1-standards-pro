import { PiRC100Validator } from '../src/core/PiRC100Validator';
import { SecurityManager } from '../src/SecurityManager';
/** @notice Reference parity against RFC 8785 (JCS) Standard */
import referenceVectors from './vectors/pirc100-reference.json';

/**
 * @file RFC8785_Vectors.test.ts
 * @description 
 * DEFINITIVE SECURITY AUDIT SUITE.
 * Engineered for 100% path exhaustion, specifically targeting internal catch-blocks 
 * in SecurityManager.ts:43 and PiRC100Validator.ts:63.
 * * @author EslaM-X | Lead Technical Architect
 * @version 2.8.2
 * @license Proprietary / PiRC-100 Standard
 */

describe('PiRC-100: RFC 8785 Deterministic Vectors & Integrity Compliance', () => {

  /**
   * @group Standard-Validation
   * Validates canonicalization against official reference vectors to ensure 
   * cross-platform deterministic consistency.
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
   * @group Hash-Integrity
   * Confirms that key insertion order does not mutate the resulting cryptographic hash.
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
   * @group Resilience-Audit
   * Stress-testing the system's ability to handle malformed data and recursive structures.
   */
  describe('Resilience Testing & Security Gates', () => {
    
    test('Gate 1: Null and Undefined Protocol Handling', () => {
      expect(PiRC100Validator.canonicalize(null as any)).toBe("null"); 
      expect(PiRC100Validator.canonicalize(undefined as any)).toBe("");
    });

    test('Gate 2: Circular Reference Interception', () => {
      const nodeA: any = { name: "NodeA" };
      const nodeB: any = { name: "NodeB" };
      nodeA.link = nodeB;
      nodeB.link = nodeA; 
      
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      expect(() => PiRC100Validator.canonicalize(nodeA)).toThrow(); 
      spy.mockRestore();
    });

    /**
     * @target SecurityManager.ts:43
     * @description Injects an enumerable getter exception to force the internal catch block
     * during the cryptographic hashing phase.
     */
    test('Gate 3: SecurityManager Internal Error Coverage', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      
      // Target: Empty check (Line 39)
      expect(SecurityManager.generatePEPProof({} as any).signature).toBe("");

      // Target: Fatal Error Catch (Line 43)
      const fatal = Object.create(null, {
        trigger: {
          get: () => { throw new Error("INTERNAL_FATAL_SIMULATION"); },
          enumerable: true 
        }
      });
      
      expect(SecurityManager.generatePEPProof(fatal).signature).toBe("");
      spy.mockRestore();
    });

    test('Gate 4: verifyPEPProof Logical Pathing', () => {
      SecurityManager.rotateKeys();
      const payload = { auth: "valid" };
      const proof = SecurityManager.generatePEPProof(payload);
      expect(SecurityManager.verifyPEPProof(payload, proof.signature, proof.version)).toBe(true);
      expect(SecurityManager.verifyPEPProof(payload, "", proof.version)).toBe(false);
    });

    test('Gate 7: Integrity Verification Edge Cases', () => {
      expect(PiRC100Validator.verifyIntegrity(null as any, "secret")).toBeNull();
      expect(typeof PiRC100Validator.verifyIntegrity({ a: 1 }, "secret")).toBe('string');
    });

    /**
     * @target PiRC100Validator.ts:63 & 83
     * @description Orchestrates a recursive 'Getter Bomb' to trigger map failures 
     * within the canonicalization loop for 100% audit compliance.
     */
    test('Gate 8: Absolute Logical Path Exhaustion', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      
      // 1. Coverage: Depth Limit (Line 34)
      const buildDeep = (l: number): any => (l <= 0 ? { x: 1 } : { n: buildDeep(l - 1) });
      expect(() => PiRC100Validator.canonicalize(buildDeep(35))).toThrow();

      // 2. Coverage: Internal Mapping Catch (Line 63)
      const poison = Object.create(null, {
        bomb: {
          get: () => { throw new Error("MAPPING_EXCEPTION"); },
          enumerable: true
        }
      });
      expect(() => PiRC100Validator.canonicalize({ data: poison })).toThrow();

      // 3. Coverage: Integrity Catch (Line 103)
      const circ: any = { id: 1 }; circ.self = circ; 
      expect(PiRC100Validator.verifyIntegrity(circ, "secret")).toBeNull();
      expect(PiRC100Validator.generateDeterministicHash(circ)).toBe("");

      // 4. Coverage: JCS Array Compliance
      expect(PiRC100Validator.canonicalize([undefined])).toBe("[null]");
      
      spy.mockRestore();
    });
  });
});
