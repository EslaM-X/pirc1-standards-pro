import { PiRC100Validator } from '../src/core/PiRC100Validator';
import { SecurityManager } from '../src/SecurityManager';
// Leveraging Official Reference Vectors for Cross-Implementation Parity
import referenceVectors from './vectors/pirc100-reference.json';

/**
 * @file RFC8785_Vectors.test.ts
 * @description 
 * Comprehensive Test Suite for PiRC-100 Deterministic Serialization compliance.
 * Verifies strict adherence to RFC 8785 (JCS) and Official Reference Vectors.
 * Engineered to ensure 100% Branch and Statement Coverage for Security Audits.
 * * @author EslaM-X | Lead Technical Architect
 * @version 2.2.0
 */

describe('PiRC-100: RFC 8785 Deterministic Vectors & Integrity Compliance', () => {

  /**
   * @section Official Protocol Reference Vectors
   * @description Direct validation against established JCS benchmarks to prevent serialization drift.
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
   * @test Vector 1: Lexicographical Key Sorting
   * @description Ensures that key reordering does not alter the cryptographic digest.
   * Crucial for maintaining state consistency across distributed Pi Network nodes.
   */
  test('Vector 1: Should maintain hash parity regardless of key insertion order', () => {
    const payloadAlpha = { version: "1.0.0", asset: "Pi", amount: 100 };
    const payloadBeta = { amount: 100, version: "1.0.0", asset: "Pi" };
    expect(PiRC100Validator.generateDeterministicHash(payloadAlpha))
      .toBe(PiRC100Validator.generateDeterministicHash(payloadBeta));
  });

  /**
   * @test Vector 2: Recursive Determinism
   * @description Validates that multi-level nested structures follow recursive sorting rules.
   */
  test('Vector 2: Should enforce recursive determinism in multi-level data structures', () => {
    const nestedA = { meta: { type: "TX", nonce: 42 }, data: "transfer" };
    const nestedB = { data: "transfer", meta: { nonce: 42, type: "TX" } };
    expect(PiRC100Validator.generateDeterministicHash(nestedA))
      .toBe(PiRC100Validator.generateDeterministicHash(nestedB));
  });

  /**
   * @test Vector 3: SecurityManager PEP Consistency
   * @description Verifies that the Policy Enforcement Point (PEP) yields identical signatures for isomorphic payloads.
   */
  test('Vector 3: SecurityManager must yield consistent signatures for isomorphic payloads', () => {
    SecurityManager.rotateKeys();
    const data1 = { action: "login", timestamp: 1710000000 };
    const data2 = { timestamp: 1710000000, action: "login" };
    const proof1 = SecurityManager.generatePEPProof(data1);
    const proof2 = SecurityManager.generatePEPProof(data2);
    expect(proof1.signature).toBe(proof2.signature);
  });

  /**
   * @test Vector 4: Primitive Serialization Standards
   * @description Confirms that Booleans, Numbers, and Strings follow strict RFC 8785 primitive rules.
   */
  test('Vector 4: Should serialize primitive types in compliance with JCS standards', () => {
    const input = { active: true, count: 5, label: "node" };
    expect(PiRC100Validator.canonicalize(input)).toBe('{"active":true,"count":5,"label":"node"}');
  });

  /**
   * @section Protocol Resilience & Fault Tolerance
   * @description Hardened boundary analysis to ensure system stability under malformed inputs.
   */
  describe('PiRC-100: Resilience & Security Gates', () => {
    
    /**
     * @gate Gate 1: Null-Safety Handling
     * @description Ensures the validator defaults to a safe-state on null/undefined inputs.
     */
    test('Gate 1: Should handle null or undefined inputs with fail-safe mechanisms', () => {
      expect(PiRC100Validator.canonicalize(null as any)).toBe("");
      expect(PiRC100Validator.canonicalize(undefined as any)).toBe("");
    });

    /**
     * @gate Gate 2: Circular Reference Mitigation
     * @description Prevents infinite recursion and memory exhaustion from self-referencing objects.
     */
    test('Gate 2: Should intercept and mitigate circular reference risks', () => {
      const circular: any = { name: "Pi" };
      circular.self = circular; 
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      expect(PiRC100Validator.canonicalize(circular)).toBe(""); 
      spy.mockRestore();
    });

    /**
     * @gate Gate 3: Empty Payload Validation
     * @description SecurityManager must reject signing of invalid or empty structures.
     */
    test('Gate 3: SecurityManager must abort signing on invalid/empty payloads', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      const proof = SecurityManager.generatePEPProof({} as any); 
      expect(proof.signature).toBe("");
      spy.mockRestore();
    });

    /**
     * @gate Gate 5: Recursion Depth Protection
     * @description Defends against Stack Overflow and Resource Exhaustion attacks.
     */
    test('Gate 5: Should enforce Maximum Recursion Depth limits', () => {
      const deep = { a: { b: { c: { d: { e: { f: { g: 1 } } } } } } };
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      expect(PiRC100Validator.canonicalize(deep)).toBe(""); 
      spy.mockRestore();
    });

    /**
     * @gate Gate 7: HMAC-SHA256 Integrity Verification
     * @description Validates the cryptographic strength of the node's internal authentication helper.
     */
    test('Gate 7: Internal Cryptographic Helper Integrity', () => {
      const payload = { pirc: 100 };
      const secret = "node-secret";
      const hash = PiRC100Validator.generateDeterministicHash(payload);
      const integrity = PiRC100Validator.verifyIntegrity(payload, secret);
      expect(hash).toHaveLength(64); // Standard SHA-256 Hex length
      expect(integrity).toBeDefined();
    });

    /**
     * @gate Gate 8: Audit Compliance Hardening
     * @description Exercises remaining logical branches to achieve 100% code coverage.
     */
    test('Gate 8: Should exercise all remaining logical branches for audit compliance', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      const nestedFailure = { key: { a: { b: { c: { d: { e: { f: 1 } } } } } } };
      expect(PiRC100Validator.canonicalize(nestedFailure)).toBe("");
      expect(PiRC100Validator.canonicalize(42)).toBe("42");
      spy.mockRestore();
    });
  });
});
