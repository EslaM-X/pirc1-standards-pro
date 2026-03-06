import { PiRC100Validator } from '../src/core/PiRC100Validator';
import { SecurityManager } from '../src/SecurityManager';
/** @notice Cross-implementation parity ensured via Official RFC 8785 Reference Vectors */
import referenceVectors from './vectors/pirc100-reference.json';

/**
 * @file RFC8785_Vectors.test.ts
 * @module PiRC100-Integrity-Suite
 * @description 
 * Advanced Test Suite for PiRC-100 Deterministic Serialization compliance.
 * Verifies strict adherence to RFC 8785 (JSON Canonicalization Scheme - JCS) 
 * to guarantee absolute cryptographic hash parity across heterogeneous environments.
 * * @audit_compliance 
 * Engineered for 100% Branch and Statement Coverage to satisfy institutional-grade security audits.
 * Implements Fault-Injection patterns to validate internal recovery and error-handling blocks.
 * * @author EslaM-X | Lead Technical Architect
 * @version 2.2.4
 */

describe('PiRC-100: RFC 8785 Deterministic Vectors & Integrity Compliance', () => {

  /**
   * @section Official Protocol Reference Vectors
   * @description Direct validation against industry benchmarks to prevent serialization drift.
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
   * @description Ensures hash parity regardless of key insertion order.
   */
  test('Vector 1: Should maintain hash parity regardless of key insertion order', () => {
    const payloadAlpha = { version: "1.0.0", asset: "Pi", amount: 100 };
    const payloadBeta = { amount: 100, version: "1.0.0", asset: "Pi" };
    expect(PiRC100Validator.generateDeterministicHash(payloadAlpha))
      .toBe(PiRC100Validator.generateDeterministicHash(payloadBeta));
  });

  /**
   * @test Vector 2: Recursive Determinism
   * @description Verifies nested object trees enforce strict deterministic sorting at all depths.
   */
  test('Vector 2: Should enforce recursive determinism in multi-level structures', () => {
    const nestedA = { meta: { type: "TX", nonce: 42 }, data: "transfer" };
    const nestedB = { data: "transfer", meta: { nonce: 42, type: "TX" } };
    expect(PiRC100Validator.generateDeterministicHash(nestedA))
      .toBe(PiRC100Validator.generateDeterministicHash(nestedB));
  });

  /**
   * @test Vector 3: SecurityManager PEP Consistency
   * @description Confirms signature idempotency for isomorphic payloads.
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
   * @section Protocol Resilience & Security Gate Hardening
   * @description Boundary analysis and adversarial input simulation to ensure architectural stability.
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

    test('Gate 5: Should enforce Maximum Recursion Depth limits to prevent Stack Overflow', () => {
      const deep = { a: { b: { c: { d: { e: { f: { g: 1 } } } } } } };
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      expect(PiRC100Validator.canonicalize(deep)).toBe(""); 
      spy.mockRestore();
    });

    /**
     * @gate Gate 8: Absolute Logical Path Exhaustion
     * @description Targets Uncovered Lines 55-63 (Validator) and 90-96 (SecurityManager) 
     * by injecting "faulty" structures to trigger catch/recovery blocks.
     */
    test('Gate 8: Should exercise all remaining logical branches for total audit coverage', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      
      /** * Trigger: PiRC100Validator Max-Depth Violation [Lines 55-63] */
      const deepFailure = { a: { b: { c: { d: { e: { f: { g: { h: 1 } } } } } } } };
      expect(PiRC100Validator.canonicalize(deepFailure)).toBe("");

      /** * Trigger: SecurityManager Internal Exception Recovery [Lines 90-96] */
      const circular: any = { id: "fault-injection" };
      circular.self = circular; 
      const secureFailure = SecurityManager.generatePEPProof(circular);
      expect(secureFailure.signature).toBe(""); 

      /** * Path: Direct Primitive pass-through for line-level coverage completion */
      expect(PiRC100Validator.canonicalize(42)).toBe("42");
      expect(PiRC100Validator.canonicalize(true)).toBe("true");
      
      spy.mockRestore();
    });
  });
});
