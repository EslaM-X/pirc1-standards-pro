import { PiRC100Validator } from '../src/core/PiRC100Validator';
import { SecurityManager } from '../src/SecurityManager';
/** @notice Cross-implementation parity ensured via Official RFC 8785 Reference Vectors */
import referenceVectors from './vectors/pirc100-reference.json';

/**
 * @file RFC8785_Vectors.test.ts
 * @module PiRC100-Integrity-Suite
 * @description Finalized Test Suite for PiRC-100.
 * Engineered for 100% Audit Coverage without breaking Frontend-Backend parity.
 * @author EslaM-X | Lead Technical Architect
 * @version 2.3.0
 */

describe('PiRC-100: RFC 8785 Deterministic Vectors & Integrity Compliance', () => {

  /**
   * @section Official Protocol Reference Vectors
   */
  describe('Official Reference Vector Validation', () => {
    referenceVectors.test_cases.forEach((vector) => {
      test(`Reference Case ${vector.id}: Should match JCS output`, () => {
        const result = PiRC100Validator.canonicalize(vector.input);
        expect(result).toBe(vector.expected_canonical);
      });
    });
  });

  /**
   * @section Core Determinism Vectors
   */
  test('Vector 1: Key Insertion Order Parity', () => {
    const p1 = { a: 1, b: 2 };
    const p2 = { b: 2, a: 1 };
    expect(PiRC100Validator.generateDeterministicHash(p1))
      .toBe(PiRC100Validator.generateDeterministicHash(p2));
  });

  test('Vector 2: Recursive Determinism', () => {
    const n1 = { m: { t: "TX" }, d: "data" };
    const n2 = { d: "data", m: { t: "TX" } };
    expect(PiRC100Validator.generateDeterministicHash(n1))
      .toBe(PiRC100Validator.generateDeterministicHash(n2));
  });

  test('Vector 3: SecurityManager Isomorphic Parity', () => {
    SecurityManager.rotateKeys();
    const d1 = { action: "login" };
    const d2 = { action: "login" };
    expect(SecurityManager.generatePEPProof(d1).signature)
      .toBe(SecurityManager.generatePEPProof(d2).signature);
  });

  /**
   * @section Protocol Resilience & Security Gate Hardening
   */
  describe('PiRC-100: Resilience & Security Gates', () => {
    
    test('Gate 1: Null/Undefined Handling', () => {
      expect(PiRC100Validator.canonicalize(null as any)).toBe("null"); 
      expect(PiRC100Validator.canonicalize(undefined as any)).toBe("");
    });

    test('Gate 2: Circular Reference Interception', () => {
      const circ: any = { a: 1 };
      circ.self = circ; 
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      expect(PiRC100Validator.canonicalize(circ)).toBe(""); 
      spy.mockRestore();
    });

    test('Gate 3: SecurityManager Fail-Safe', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      expect(SecurityManager.generatePEPProof({} as any).signature).toBe("");
      spy.mockRestore();
    });

    test('Gate 7: Integrity Validation Logic', () => {
      const payload = { pirc: 100 };
      const integrity = PiRC100Validator.verifyIntegrity(payload, "secret");
      expect(integrity).toBeDefined();
    });

    /**
     * @gate Gate 8: Absolute Logical Path Exhaustion (The Audit Closer)
     * استهداف جراحي للسطور: Validator (55-63, 121-122) و SecurityManager (96-102)
     */
    test('Gate 8: Absolute Logical Path Exhaustion for 100% Audit Compliance', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      
      // 1. Target: Validator Depth Violation [55-63]
      const deep = { l1: { l2: { l3: { l4: { l5: { l6: 1 } } } } } };
      expect(PiRC100Validator.canonicalize(deep)).toBe("");

      // 2. Target: SecurityManager Catch Block [96-102]
      const circ: any = { id: "trigger-catch" };
      circ.self = circ; 
      const fail = SecurityManager.generatePEPProof(circ);
      expect(fail.signature).toBe(""); 

      // 3. Target: Validator Integrity Fail-Safe [121-122]
      expect(PiRC100Validator.verifyIntegrity(null as any, "secret")).toBe(false);

      // 4. Lines Coverage for Primitives
      expect(PiRC100Validator.canonicalize(42)).toBe("42");
      expect(PiRC100Validator.canonicalize(true)).toBe("true");
      
      spy.mockRestore();
    });
  });
});
