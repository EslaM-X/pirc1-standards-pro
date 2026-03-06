import { PiRC100Validator } from '../src/core/PiRC100Validator';
import { SecurityManager } from '../src/SecurityManager';
/** @notice Leveraging Official Reference Vectors for Cross-Implementation Parity */
import referenceVectors from './vectors/pirc100-reference.json';

/**
 * @file RFC8785_Vectors.test.ts
 * @description 
 * Comprehensive Test Suite for PiRC-100 Deterministic Serialization compliance.
 * Verifies strict adherence to RFC 8785 (JCS) and Official Reference Vectors.
 * Engineered for 100% Branch and Statement Coverage to satisfy security audit requirements.
 * @author EslaM-X | Lead Technical Architect
 * @version 2.2.4
 */

describe('PiRC-100: RFC 8785 Deterministic Vectors & Integrity Compliance', () => {

  /**
   * @section Official Protocol Reference Vectors
   * @description Direct validation against industry-standard benchmarks to prevent 
   * serialization drift and ensure cross-platform compatibility.
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
   * @description Verifies that the order of key insertion does not affect the final hash,
   * a fundamental requirement for distributed ledger state consistency.
   */
  test('Vector 1: Should maintain hash parity regardless of key insertion order', () => {
    const payloadAlpha = { version: "1.0.0", asset: "Pi", amount: 100 };
    const payloadBeta = { amount: 100, version: "1.0.0", asset: "Pi" };
    expect(PiRC100Validator.generateDeterministicHash(payloadAlpha))
      .toBe(PiRC100Validator.generateDeterministicHash(payloadBeta));
  });

  /**
   * @test Vector 2: Recursive Determinism
   * @description Ensures that nested objects are sorted recursively, maintaining 
   * deterministic output at every depth of the data structure.
   */
  test('Vector 2: Should enforce recursive determinism in multi-level structures', () => {
    const nestedA = { meta: { type: "TX", nonce: 42 }, data: "transfer" };
    const nestedB = { data: "transfer", meta: { nonce: 42, type: "TX" } };
    expect(PiRC100Validator.generateDeterministicHash(nestedA))
      .toBe(PiRC100Validator.generateDeterministicHash(nestedB));
  });

  /**
   * @test Vector 3: SecurityManager PEP Consistency
   * @description Validates that the SecurityManager yields identical HMAC signatures
   * for isomorphic payloads, ensuring deterministic Policy Enforcement.
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
   * @description Confirms JCS-compliant serialization for booleans, numbers, and strings.
   */
  test('Vector 4: Should serialize primitive types in compliance with JCS standards', () => {
    const input = { active: true, count: 5, label: "node" };
    expect(PiRC100Validator.canonicalize(input)).toBe('{"active":true,"count":5,"label":"node"}');
  });

  /**
   * @section Protocol Resilience & Fault Tolerance
   * @description Hardened boundary analysis to ensure system stability and 
   * predictable failure modes under malformed or adversarial inputs.
   */
  describe('PiRC-100: Resilience & Security Gates', () => {
    
    /**
     * @gate Gate 1: Null-Safety Protocol
     */
    test('Gate 1: Should handle null or undefined inputs with fail-safe mechanisms', () => {
      expect(PiRC100Validator.canonicalize(null as any)).toBe("null"); 
      expect(PiRC100Validator.canonicalize(undefined as any)).toBe("");
    });

    /**
     * @gate Gate 2: Circular Reference Mitigation
     */
    test('Gate 2: Should intercept and mitigate circular reference risks', () => {
      const circular: any = { name: "Pi" };
      circular.self = circular; 
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      expect(PiRC100Validator.canonicalize(circular)).toBe(""); 
      spy.mockRestore();
    });

    /**
     * @gate Gate 3: Integrity-First Signing Abort
     */
    test('Gate 3: SecurityManager must abort signing on invalid/empty payloads', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      expect(SecurityManager.generatePEPProof({} as any).signature).toBe("");
      expect(SecurityManager.generatePEPProof(null as any).signature).toBe("");
      spy.mockRestore();
    });

    /**
     * @gate Gate 5: Recursion Depth Guard
     */
    test('Gate 5: Should enforce Maximum Recursion Depth limits', () => {
      const deep = { a: { b: { c: { d: { e: { f: { g: 1 } } } } } } };
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      expect(PiRC100Validator.canonicalize(deep)).toBe(""); 
      spy.mockRestore();
    });

    /**
     * @gate Gate 7: Cryptographic Verification Utilities
     */
    test('Gate 7: Internal Cryptographic Helper Integrity', () => {
      const payload = { pirc: 100 };
      const secret = "node-secret";
      const hash = PiRC100Validator.generateDeterministicHash(payload);
      const integrity = PiRC100Validator.verifyIntegrity(payload, secret);
      expect(hash).toHaveLength(64);
      expect(integrity).toBeDefined();
    });

    /**
     * @gate Gate 8: Absolute Branch & Line Coverage Hardening
     * @description Explicitly targets remaining logical branches (Validator lines 55-63 
     * and SecurityManager lines 90-96) to achieve a complete 100% audit-ready coverage report.
     */
    test('Gate 8: Should exercise all remaining logical branches for audit compliance', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      
      // Target 1: Triggering deep nesting failure logic in PiRC100Validator [Lines 55-63]
      const deepFailure = { a: { b: { c: { d: { e: { f: { g: { h: 1 } } } } } } } };
      expect(PiRC100Validator.canonicalize(deepFailure)).toBe("");

      // Target 2: Forcing SecurityManager catch block via circular fault injection [Lines 90-96]
      const circular: any = { id: "fault-injection" };
      circular.self = circular; 
      const secureFailure = SecurityManager.generatePEPProof(circular);
      expect(secureFailure.signature).toBe("");

      // Target 3: Confirming deterministic primitive pass-through to ensure full branch coverage
      expect(PiRC100Validator.canonicalize(42)).toBe("42");
      
      spy.mockRestore();
    });
  });
});
