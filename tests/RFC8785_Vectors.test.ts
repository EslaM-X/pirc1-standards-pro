import { PiRC100Validator } from '../src/core/PiRC100Validator';
import { SecurityManager } from '../src/SecurityManager';
/** @notice Cross-implementation parity ensured via Official RFC 8785 Reference Vectors */
import referenceVectors from './vectors/pirc100-reference.json';

/**
 * @file RFC8785_Vectors.test.ts
 * @module PiRC-100-Integrity-Suite
 * @description 
 * Hardened Test Suite for RFC 8785 Deterministic Serialization and Integrity Compliance.
 * Specifically engineered for 100% path exhaustion, targeting deep catch-blocks 
 * and edge-case boundary conditions in the PiRC-100 standard.
 * * @author EslaM-X | Lead Technical Architect
 * @version 2.7.2
 */

describe('PiRC-100: RFC 8785 Deterministic Vectors & Integrity Compliance', () => {

  /**
   * @group Standard-Compliance
   * @description Validates implementation against official JCS (JSON Canonicalization Scheme) vectors.
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
   * @group Consistency-Checks
   * @description Verifies that object key ordering does not affect the generated hash.
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
   * @group Resilience-Security
   * @description Stress testing security gates and internal error handling mechanisms.
   */
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
     * @target SecurityManager.ts:43
     * @description Forces internal catch-block execution using a non-serializable 
     * property descriptor to trigger a runtime exception during key iteration.
     */
    test('Gate 3: SecurityManager Internal Error Coverage', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      
      // Target: Empty payload rejection (Line 39)
      expect(SecurityManager.generatePEPProof({} as any).signature).toBe("");

      // Target: Internal Error Catch (Line 43)
      const poisoned = Object.create(null, {
        trigger: {
          get: () => { throw new Error("V8_INTERNAL_SIMULATION"); },
          enumerable: true
        }
      });
      expect(SecurityManager.generatePEPProof(poisoned).signature).toBe("");
      
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
     * @gate Gate 8
     * @target PiRC100Validator.ts:63 & 103
     * @description Executes absolute path exhaustion by injecting a "Getter Bomb" 
     * inside the serialization loop to ensure the catch-block is functionally covered.
     */
    test('Gate 8: Absolute Path Exhaustion for 100% Audit Compliance', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      
      // 1. Recursive Depth Protection (Line 50)
      const buildDeep = (l: number): any => (l <= 0 ? { x: 1 } : { n: buildDeep(l - 1) });
      expect(() => PiRC100Validator.canonicalize(buildDeep(35))).toThrow();

      // 2. Internal Mapping Exception (Line 63)
      const bomb = Object.create({}, {
        'critical_failure': { 
          get: () => { throw new Error("MAPPING_FAIL"); }, 
          enumerable: true 
        }
      });
      expect(() => PiRC100Validator.canonicalize({ data: bomb })).toThrow();

      // 3. Hash Generation Integrity Catch (Line 103)
      const circular: any = { id: "pirc-audit" }; circular.self = circular; 
      expect(PiRC100Validator.verifyIntegrity(circular, "secret")).toBeNull();
      expect(PiRC100Validator.generateDeterministicHash(circular)).toBe("");

      // 4. Array Normalization
      expect(PiRC100Validator.canonicalize([undefined])).toBe("[null]");
      
      spy.mockRestore();
    });
  });
});
