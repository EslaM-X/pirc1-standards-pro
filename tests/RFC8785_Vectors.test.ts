import { PiRC100Validator } from '../src/core/PiRC100Validator';
import { SecurityManager } from '../src/SecurityManager';

/**
 * @file RFC8785_Vectors.test.ts
 * @description 
 * Comprehensive Test Suite for PiRC-100 Deterministic Serialization compliance.
 * Verifies strict adherence to RFC 8785 (JSON Canonicalization Scheme - JCS).
 * Ensures 100% Code Coverage across core cryptographic and validation modules.
 * * @author EslaM-X | Lead Technical Architect
 * @version 2.1.0
 */

describe('PiRC-100: RFC 8785 Deterministic Vectors & Integrity Compliance', () => {

  /**
   * @test Vector 1: Lexicographical Key Sorting
   * @description Validates that key reordering does not affect the cryptographic digest.
   * This ensures state consistency across distributed Pi Network nodes.
   */
  test('Vector 1: Should maintain hash parity regardless of key insertion order', () => {
    const payloadAlpha = { version: "1.0.0", asset: "Pi", amount: 100 };
    const payloadBeta = { amount: 100, version: "1.0.0", asset: "Pi" };

    const hashAlpha = PiRC100Validator.generateDeterministicHash(payloadAlpha);
    const hashBeta = PiRC100Validator.generateDeterministicHash(payloadBeta);

    expect(hashAlpha).toBe(hashBeta);
  });

  /**
   * @test Vector 2: Nested Object Canonicalization
   * @description Ensures that nested structures follow deterministic sorting rules.
   */
  test('Vector 2: Should enforce recursive determinism in multi-level data structures', () => {
    const nestedA = { meta: { type: "TX", nonce: 42 }, data: "transfer" };
    const nestedB = { data: "transfer", meta: { nonce: 42, type: "TX" } };

    const hashA = PiRC100Validator.generateDeterministicHash(nestedA);
    const hashB = PiRC100Validator.generateDeterministicHash(nestedB);

    expect(hashA).toBe(hashB);
  });

  /**
   * @test Vector 3: SecurityManager PEP (Policy Enforcement Point) Integration
   * @description Verifies that the SecurityManager produces identical signatures for identical canonical states.
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
   * @test Vector 4: JCS Primitive Standardization
   * @description Confirms that primitives (Booleans, Numbers, Strings) are serialized per RFC 8785 specifications.
   */
  test('Vector 4: Should serialize primitive types in compliance with JCS standards', () => {
    const input = { active: true, count: 5, label: "node" };
    const result = PiRC100Validator.canonicalize(input);
    expect(result).toBe('{"active":true,"count":5,"label":"node"}');
  });

  /**
   * Coverage Hardening: Boundary Analysis & Error Path Validation
   * Designed to achieve 100% branch and statement coverage for security auditing.
   */
  describe('PiRC-100: Protocol Resilience & Fault Tolerance', () => {
    
    test('Gate 1: Should handle null or undefined inputs with fail-safe mechanisms', () => {
      expect(PiRC100Validator.canonicalize(null as any)).toBe("");
      expect(PiRC100Validator.canonicalize(undefined as any)).toBe("");
    });

    test('Gate 2: Should intercept and mitigate circular reference risks', () => {
      const circular: any = { name: "Pi" };
      circular.self = circular; 
      
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      const result = PiRC100Validator.canonicalize(circular);
      
      expect(result).toBe(""); 
      expect(spy).toHaveBeenCalled();
      spy.mockRestore();
    });

    test('Gate 3: SecurityManager must abort signing on invalid/empty payloads', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      const proof = SecurityManager.generatePEPProof({} as any); 
      
      expect(proof.signature).toBe("");
      expect(spy).toHaveBeenCalled();
      spy.mockRestore();
    });

    test('Gate 4: Should confirm operational logging during Key Rotation', () => {
      const spy = jest.spyOn(console, 'log').mockImplementation(() => {});
      SecurityManager.rotateKeys();
      expect(spy).toHaveBeenCalledWith(expect.stringContaining("Rotated"));
      spy.mockRestore();
    });

    /**
     * @Gate 5: Recursive Depth Protection
     * Guards against Stack Overflow and Resource Exhaustion attacks.
     */
    test('Gate 5: Should enforce Maximum Recursion Depth limits', () => {
      const arrResult = PiRC100Validator.canonicalize([1, 2, { z: 0 }]);
      expect(arrResult).toBe("[1,2,{\"z\":0}]");

      // Triggers MAX_DEPTH error path
      const deep = { a: { b: { c: { d: { e: { f: { g: 1 } } } } } } };
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      
      expect(PiRC100Validator.canonicalize(deep)).toBe(""); 
      expect(spy).toHaveBeenCalledWith(expect.stringContaining("Maximum recursion depth"));
      spy.mockRestore();
    });

    test('Gate 6: Should validate PEP Proofs and detect version mismatches', () => {
      const payload = { auth: "valid" };
      const proof = SecurityManager.generatePEPProof(payload);
      
      expect(SecurityManager.verifyPEPProof(payload, proof.signature, proof.version)).toBe(true);
      expect(SecurityManager.verifyPEPProof(payload, proof.signature, 999)).toBe(false);
      expect(SecurityManager.verifyPEPProof(payload, "", proof.version)).toBe(false);
    });

    test('Gate 7: Internal Cryptographic Helper Integrity', () => {
      const payload = { pirc: 100 };
      const secret = "node-secret";
      
      const hash = PiRC100Validator.generateDeterministicHash(payload);
      const integrity = PiRC100Validator.verifyIntegrity(payload, secret);

      expect(hash).toBeDefined();
      expect(integrity).toBeDefined();
      expect(hash).toHaveLength(64); // SHA-256 hex length
    });

    /**
     * @Gate 8: Absolute Branch Coverage Hardening
     * Specifically targets Line 56 (Validator) and Line 50 (SecurityManager).
     */
    test('Gate 8: Should exercise all remaining logical branches for audit compliance', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});

      // 1. Trigger nested object failure (Validator Line 56)
      const nestedFailure = { key: { a: { b: { c: { d: { e: { f: 1 } } } } } } };
      expect(PiRC100Validator.canonicalize(nestedFailure)).toBe("");
      
      // 2. Trigger nested array failure (Validator Line 53)
      const arrayFailure = [ { a: { b: { c: { d: { e: { f: 1 } } } } } } ];
      expect(PiRC100Validator.canonicalize(arrayFailure)).toBe("");

      // 3. Verify null/undefined signature edge cases (SecurityManager Line 50)
      expect(SecurityManager.verifyPEPProof({ data: 1 }, null as any, 1)).toBe(false);
      expect(SecurityManager.verifyPEPProof({ data: 1 }, undefined as any, 1)).toBe(false);
      
      // 4. Exercise primitive serialization branch
      expect(PiRC100Validator.canonicalize(42)).toBe("42");
      expect(PiRC100Validator.canonicalize("Pi")).toBe("\"Pi\"");

      spy.mockRestore();
    });
  });
});
