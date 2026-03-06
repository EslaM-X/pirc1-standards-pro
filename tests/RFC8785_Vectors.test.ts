import { PiRC100Validator } from '../src/core/PiRC100Validator';
import { SecurityManager } from '../src/SecurityManager';

/**
 * @file RFC8785_Vectors.test.ts
 * @description 
 * Formal Test Suite for PiRC-100 Deterministic Serialization compliance.
 * Verifies that the implementation adheres to RFC 8785 (JCS) and prevents 
 * hash divergence across distributed nodes.
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

    // Assert that both hashes are identical despite the input order mutation
    expect(hashAlpha).toBe(hashBeta);
    console.log(`[Test Success] Verified Deterministic Hash: ${hashAlpha}`);
  });

  /**
   * Test Vector 2: Nested Object Determinism
   * Verifies that the canonicalization engine recurses correctly through nested structures.
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
   * Validates that the SecurityManager produces consistent signatures using RFC 8785.
   */
  test('Vector 3: SecurityManager must generate identical signatures for reordered payloads', () => {
    // Ensure keys are initialized
    SecurityManager.rotateKeys();

    const data1 = { action: "login", timestamp: 1710000000 };
    const data2 = { timestamp: 1710000000, action: "login" };

    const proof1 = SecurityManager.generatePEPProof(data1);
    const proof2 = SecurityManager.generatePEPProof(data2);

    // Signatures must match because of the underlying PiRC100Validator.canonicalize call
    expect(proof1.signature).toBe(proof2.signature);
    expect(proof1.version).toBe(proof2.version);
  });

  /**
   * Test Vector 4: Primitive Type Consistency
   * Ensures numbers, strings, and booleans are serialized uniformly.
   */
  test('Vector 4: Should handle primitive types according to JCS standards', () => {
    const input = { active: true, count: 5, label: "node" };
    const result = PiRC100Validator.canonicalize(input);

    // Expected RFC 8785 format: keys sorted, no whitespace
    expect(result).toBe('{"active":true,"count":5,"label":"node"}');
  });
});

