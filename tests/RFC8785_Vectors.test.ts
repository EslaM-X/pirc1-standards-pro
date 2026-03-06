import { PiRC100Validator } from '../src/core/PiRC100Validator';
import { SecurityManager } from '../src/SecurityManager';

/**
 * @file RFC8785_Vectors.test.ts
 * @description 
 * Formal Test Suite for PiRC-100 Deterministic Serialization compliance.
 * Verifies RFC 8785 (JCS) adherence and secures 100% coverage across all modules.
 * @author EslaM-X | Lead Technical Architect
 */

describe('PiRC-100: RFC 8785 Deterministic Vectors & Integrity', () => {

  /**
   * Test Vector 1: Lexicographical Key Sorting
   * Ensures that reordering keys does not mutate the final cryptographic hash.
   */
  test('Vector 1: Should maintain hash consistency regardless of key order', () => {
    const payloadAlpha = { version: "1.0.0", asset: "Pi", amount: 100 };
    const payloadBeta = { amount: 100, version: "1.0.0", asset: "Pi" };

    const hashAlpha = PiRC100Validator.generateDeterministicHash(payloadAlpha);
    const hashBeta = PiRC100Validator.generateDeterministicHash(payloadBeta);

    expect(hashAlpha).toBe(hashBeta);
  });

  /**
   * Test Vector 2: Nested Object Determinism
   */
  test('Vector 2: Should enforce determinism in nested data structures', () => {
    const nestedA = { meta: { type: "TX", nonce: 42 }, data: "transfer" };
    const nestedB = { data: "transfer", meta: { nonce: 42, type: "TX" } };

    const hashA = PiRC100Validator.generateDeterministicHash(nestedA);
    const hashB = PiRC100Validator.generateDeterministicHash(nestedB);

    expect(hashA).toBe(hashB);
  });

  /**
   * Test Vector 3: SecurityManager PEP Integration
   */
  test('Vector 3: SecurityManager must generate identical signatures for reordered payloads', () => {
    SecurityManager.rotateKeys();
    const data1 = { action: "login", timestamp: 1710000000 };
    const data2 = { timestamp: 1710000000, action: "login" };

    const proof1 = SecurityManager.generatePEPProof(data1);
    const proof2 = SecurityManager.generatePEPProof(data2);

    expect(proof1.signature).toBe(proof2.signature);
  });

  /**
   * Test Vector 4: Primitive Type Consistency
   */
  test('Vector 4: Should handle primitive types according to JCS standards', () => {
    const input = { active: true, count: 5, label: "node" };
    const result = PiRC100Validator.canonicalize(input);
    expect(result).toBe('{"active":true,"count":5,"label":"node"}');
  });

  /**
   * Coverage Hardening: Boundary & Error Conditions
   * Targets 100% function coverage and 100% line coverage.
   */
  describe('PiRC-100: Protocol Resilience & Error Path Coverage', () => {
    
    test('Gate 1: Should handle null/undefined payloads gracefully', () => {
      expect(PiRC100Validator.canonicalize(null as any)).toBe("");
      expect(PiRC100Validator.canonicalize(undefined as any)).toBe("");
    });

    test('Gate 2: Should catch and log serialization errors for circular references', () => {
      const circular: any = { name: "Pi" };
      circular.self = circular; // Trigger explicit circular check
      
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      const result = PiRC100Validator.canonicalize(circular);
      
      expect(result).toBe(""); 
      expect(spy).toHaveBeenCalled();
      spy.mockRestore();
    });

    test('Gate 3: SecurityManager should fail safely on invalid payloads', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      const proof = SecurityManager.generatePEPProof({} as any); 
      
      expect(proof.signature).toBe("");
      expect(spy).toHaveBeenCalled();
      spy.mockRestore();
    });

    test('Gate 4: Should verify key rotation logging', () => {
      const spy = jest.spyOn(console, 'log').mockImplementation(() => {});
      SecurityManager.rotateKeys();
      expect(spy).toHaveBeenCalledWith(expect.stringContaining("Rotated"));
      spy.mockRestore();
    });

    /**
     * @Gate 5: Architectural Integrity Check
     * Blocks deep nesting attacks using a level-10 object to trigger MAX_DEPTH protection.
     */
    test('Gate 5: Should handle Arrays and nested Depth limits', () => {
      const arrResult = PiRC100Validator.canonicalize([1, 2, { z: 0 }]);
      expect(arrResult).toBe("[1,2,{\"z\":0}]");

      const deep = { a: { b: { c: { d: { e: { f: { g: { h: { i: { j: 1 } } } } } } } } } };
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      
      expect(PiRC100Validator.canonicalize(deep)).toBe(""); 
      expect(spy).toHaveBeenCalledWith(expect.stringContaining("Maximum recursion depth"));
      spy.mockRestore();
    });

    test('Gate 6: Should verify PEP Proof and handle version mismatch', () => {
      const payload = { auth: "valid" };
      const proof = SecurityManager.generatePEPProof(payload);
      
      expect(SecurityManager.verifyPEPProof(payload, proof.signature, proof.version)).toBe(true);
      expect(SecurityManager.verifyPEPProof(payload, proof.signature, 999)).toBe(false);
      expect(SecurityManager.verifyPEPProof(payload, "", proof.version)).toBe(false);
    });

    test('Gate 7: Should verify Cryptographic Helper functions directly', () => {
      const payload = { pirc: 100 };
      const secret = "node-secret";
      
      const hash = PiRC100Validator.generateDeterministicHash(payload);
      const integrity = PiRC100Validator.verifyIntegrity(payload, secret);

      expect(hash).toBeDefined();
      expect(integrity).toBeDefined();
      expect(hash.length).toBe(64);
    });

    /**
     * @Gate 8: Absolute Branch Coverage Hardening
     * Targets remaining branches in Validator (Line 53) and SecurityManager (Line 50).
     */
    test('Gate 8: Should cover all remaining logic branches', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});

      // 1. Force entry into the catch block through nested depth failure (Validator Line 53)
      // This specifically triggers the "Recursive limit reached" error found in logs
      const nestedFailure = { a: { b: { c: { d: { e: { f: "trigger" } } } } } };
      expect(PiRC100Validator.canonicalize(nestedFailure)).toBe("");
      
      // 2. Test non-string/invalid signature types (SecurityManager Line 50)
      expect(SecurityManager.verifyPEPProof({ data: 1 }, null as any, 1)).toBe(false);
      expect(SecurityManager.verifyPEPProof({ data: 1 }, undefined as any, 1)).toBe(false);
      
      // 3. Test simple primitives to cover Phase 3 branch
      expect(PiRC100Validator.canonicalize(42)).toBe("42");
      expect(PiRC100Validator.canonicalize("Pi")).toBe("\"Pi\"");

      spy.mockRestore();
    });
  });
});
