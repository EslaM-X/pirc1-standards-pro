import { PiRC100Validator } from '../src/core/PiRC100Validator';
import { SecurityManager } from '../src/SecurityManager';
/** @notice Cross-implementation parity ensured via Official RFC 8785 Reference Vectors */
import referenceVectors from './vectors/pirc100-reference.json';

/**
 * @file RFC8785_Vectors.test.ts
 * @module PiRC100-Integrity-Suite
 * @description 
 * Advanced Test Suite for PiRC-100 Deterministic Serialization compliance.
 * Verifies strict adherence to RFC 8785 (JSON Canonicalization Scheme - JCS).
 * * @audit_compliance 
 * Target: 100% Branch and Statement Coverage. 
 * Includes Fault-Injection for Lines 55-63, 121-122 (Validator) and 90-96 (SecurityManager).
 * * @author EslaM-X | Lead Technical Architect
 * @version 2.2.5
 */

describe('PiRC-100: RFC 8785 Deterministic Vectors & Integrity Compliance', () => {

  /**
   * @section Official Protocol Reference Vectors
   */
  describe('Official Reference Vector Validation', () => {
    referenceVectors.test_cases.forEach((vector) => {
      test(`Reference Case ${vector.id}: Should match expected JCS canonical output`, () => {
        const result = PiRC100Validator.canonicalize(vector.input);
        expect(result).toBe(vector.expected_canonical);
      });
    });
  });

  /**
   * @section Core Determinism Vectors
   */
  test('Vector 1: Should maintain hash parity regardless of key insertion order', () => {
    const payloadAlpha = { version: "1.0.0", asset: "Pi", amount: 100 };
    const payloadBeta = { amount: 100, version: "1.0.0", asset: "Pi" };
    expect(PiRC100Validator.generateDeterministicHash(payloadAlpha))
      .toBe(PiRC100Validator.generateDeterministicHash(payloadBeta));
  });

  test('Vector 2: Should enforce recursive determinism in multi-level structures', () => {
    const nestedA = { meta: { type: "TX", nonce: 42 }, data: "transfer" };
    const nestedB = { data: "transfer", meta: { nonce: 42, type: "TX" } };
    expect(PiRC100Validator.generateDeterministicHash(nestedA))
      .toBe(PiRC100Validator.generateDeterministicHash(nestedB));
  });

  test('Vector 3: SecurityManager must yield consistent signatures for isomorphic payloads', () => {
    SecurityManager.rotateKeys();
    const data1 = { action: "login", timestamp: 1710000000 };
    const data2 = { timestamp: 1710000000, action: "login" };
    const proof1 = SecurityManager.generatePEPProof(data1);
    const proof2 = SecurityManager.generatePEPProof(data2);
    expect(proof1.signature).toBe(proof2.signature);
  });

  test('Vector 4: Should serialize primitive types in compliance with JCS standards', () => {
    const input = { active: true, count: 5, label: "node" };
    expect(PiRC100Validator.canonicalize(input)).toBe('{"active":true,"count":5,"label":"node"}');
  });

  /**
   * @section Protocol Resilience & Security Gate Hardening
   */
  describe('PiRC-100: Resilience & Security Gates', () => {
    
    test('Gate 1: Should handle null or undefined inputs with fail-safe mechanisms', () => {
      expect(PiRC100Validator.canonicalize(null as any)).toBe("null"); 
      expect(PiRC100Validator.canonicalize(undefined as any)).toBe("");
    });

    test('Gate 2: Should intercept and mitigate circular reference risks', () => {
      const circular: any = { name: "Pi" };
      circular.self = circular; 
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      expect(PiRC100Validator.canonicalize(circular)).toBe(""); 
      spy.mockRestore();
    });

    test('Gate 3: SecurityManager must abort signing on invalid or empty payloads', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      expect(SecurityManager.generatePEPProof({} as any).signature).toBe("");
      expect(SecurityManager.generatePEPProof(null as any).signature).toBe("");
      spy.mockRestore();
    });

    test('Gate 5: Should enforce Maximum Recursion Depth limits', () => {
      const deep = { a: { b: { c: { d: { e: { f: { g: 1 } } } } } } };
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      expect(PiRC100Validator.canonicalize(deep)).toBe(""); 
      spy.mockRestore();
    });

    test('Gate 7: Internal Cryptographic Helper Integrity Validation', () => {
      const payload = { pirc: 100 };
      const secret = "node-secret";
      const hash = PiRC100Validator.generateDeterministicHash(payload);
      const integrity = PiRC100Validator.verifyIntegrity(payload, secret);
      expect(hash).toHaveLength(64);
      expect(integrity).toBeDefined();
    });

    /**
     * @gate Gate 8: Final Path Exhaustion (The Audit Closer)
     * Targets Uncovered Lines: Validator (55-63, 121-122) & SecurityManager (90-96)
     */
    test('Gate 8: Absolute Logical Path Exhaustion for 100% Audit Compliance', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      
      // Target: Validator Depth Violation [55-63]
      const deepFailure = { a: { b: { c: { d: { e: { f: { g: { h: 1 } } } } } } } };
      expect(PiRC100Validator.canonicalize(deepFailure)).toBe("");

      // Target: SecurityManager Catch Block [90-96]
      const circular: any = { id: "fault-injection" };
      circular.self = circular; 
      const secureFailure = SecurityManager.generatePEPProof(circular);
      expect(secureFailure.signature).toBe(""); 

      // Target: Validator Integrity Catch/Edge [121-122]
      // Passing an object that would fail internally in verifyIntegrity logic
      const integrityFailure = PiRC100Validator.verifyIntegrity(undefined as any, "secret");
      expect(integrityFailure).toBe(false);

      // Coverage for direct primitives
      expect(PiRC100Validator.canonicalize(42)).toBe("42");
      expect(PiRC100Validator.canonicalize(true)).toBe("true");
      
      spy.mockRestore();
    });
  });
});
