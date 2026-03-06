import { PiRC100Validator } from '../src/core/PiRC100Validator';
import { SecurityManager } from '../src/SecurityManager';
/** @notice Cross-implementation parity ensured via Official RFC 8785 Reference Vectors */
import referenceVectors from './vectors/pirc100-reference.json';

/**
 * @file RFC8785_Vectors.test.ts
 * @module PiRC-100-Security-Audit
 * @description 
 * Hardened Test Suite for 100% Coverage Compliance.
 * Targets specific V8 internal failure paths: SecurityManager[43], Validator[63].
 * @author EslaM-X | Lead Technical Architect
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
     * @target Coverage: SecurityManager Line 39 & 43
     * Using a BigInt in a way that forces a serialization error inside the manager.
     */
    test('Gate 3: SecurityManager Internal Error Coverage', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      
      // Target Line 39 (Empty check)
      expect(SecurityManager.generatePEPProof({}).signature).toBe("");

      // Target Line 43 (Catch Block)
      // BigInt cannot be serialized by standard JSON/JCS without explicit handling
      // This forces the internal Validator.generateDeterministicHash to throw.
      const fatalObj = { 
        data: { 
          get fatal() { throw new Error("INTERNAL_FAIL"); } 
        } 
      };
      expect(SecurityManager.generatePEPProof(fatalObj as any).signature).toBe("");
      
      spy.mockRestore();
    });

    /**
     * @gate Gate 8: Absolute Logical Path Exhaustion
     * @description Targeting Validator Line 63 via Recursive Property Crash.
     */
    test('Gate 8: Validator Line 63 Mapping Failure Coverage', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      
      // 1. Target: Validator Depth Violation (Line 50)
      const buildDeep = (l: number): any => (l <= 0 ? { e: 1 } : { n: buildDeep(l - 1) });
      expect(() => PiRC100Validator.canonicalize(buildDeep(35))).toThrow("MAX_DEPTH_REACHED");

      // 2. Target: Validator Sub-Structure Mapping Catch (Line 63)
      // This specifically targets the .map() catch inside the object handler.
      const errorTrigger = {
        level1: {
          get level2() { throw new Error("MAPPING_EXCEPTION"); }
        }
      };
      expect(() => PiRC100Validator.canonicalize(errorTrigger)).toThrow();

      // 3. Target: Validator Integrity Catch Block (Line 103)
      const circ: any = { id: "audit-trigger" };
      circ.self = circ; 
      expect(PiRC100Validator.verifyIntegrity(circ, "secret")).toBeNull();
      expect(PiRC100Validator.generateDeterministicHash(circ)).toBe("");

      // 4. Target: JCS Array Undefined Path
      expect(PiRC100Validator.canonicalize([undefined])).toBe("[null]");
      
      spy.mockRestore();
    });
  });
});
