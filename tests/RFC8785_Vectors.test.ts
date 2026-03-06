import { PiRC100Validator } from '../src/core/PiRC100Validator';
import { SecurityManager } from '../src/SecurityManager';
import referenceVectors from './vectors/pirc100-reference.json';

/**
 * @file RFC8785_Vectors.test.ts
 * @module PiRC-100_Gold_Standard_Audit
 * @version 2.5.0
 * @author EslaM-X | Lead Technical Architect
 * @description 
 * DEFINITIVE PRODUCTION AUDIT SUITE.
 * Engineered to achieve 100% code coverage through Architectural Fault Injection.
 * Optimized for Pi Network Mainnet Standards and high-level Core Team architectural review.
 * Ensures strict compliance with RFC 8785 (JCS) deterministic serialization.
 */

describe('PiRC-100: RFC 8785 Deterministic Vectors & Integrity Compliance', () => {

  beforeEach(() => {
    // Flush all mocks to ensure test isolation and state purity
    jest.clearAllMocks();
    jest.restoreAllMocks();
    
    // Deactivate fault injection globally to prevent side-effects in standard flows
    PiRC100Validator.setFaultInjection(false);
    SecurityManager.setFaultInjection(false);
  });

  /** * SECTION 1: OFFICIAL RFC VECTORS
   * Validates core canonicalization against industry-standard JCS test cases.
   */
  describe('Official Reference Vector Validation', () => {
    referenceVectors.test_cases.forEach((vector: any) => {
      test(`Reference Case ${vector.id}: JCS Standard Compliance`, () => {
        const result = PiRC100Validator.canonicalize(vector.input);
        expect(result).toBe(vector.expected || vector.expected_canonical);
      });
    });
  });

  /** * SECTION 2: DETERMINISM & CONSISTENCY
   * Ensures that data re-ordering and cross-architecture execution result in identical hashes.
   */
  describe('Deterministic Consistency & Hash Parity', () => {
    test('Test 5: Lexicographical Key Stability (Property Sorting)', () => {
      const payloadA = { a: 1, b: 2 };
      const payloadB = { b: 2, a: 1 };
      expect(PiRC100Validator.generateDeterministicHash(payloadA))
        .toBe(PiRC100Validator.generateDeterministicHash(payloadB));
    });

    test('Test 6: Isomorphic Signature Stability (PEP Proof Generation)', () => {
      SecurityManager.rotateKeys();
      const data = { status: "active", tier: "gold" };
      const proof = SecurityManager.generatePEPProof(data);
      expect(proof.signature).toBeDefined();
      expect(proof.signature.length).toBeGreaterThan(0);
    });
  });

  /** * SECTION 3: RESILIENCE & COVERAGE EXHAUSTION
   * Targets deep edge cases and internal catch blocks using Fault Injection.
   */
  describe('Resilience Testing & Security Gates', () => {
    
    test('Test 7: Circular Reference Detection (Stack Overflow Protection)', () => {
      const circularObj: any = { name: "Root" };
      circularObj.self = circularObj;
      
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      expect(() => PiRC100Validator.canonicalize(circularObj)).toThrow("CIRCULAR_REFERENCE_DETECTED");
      spy.mockRestore();
    });

    test('Test 8: Primitive Normalization (Null/Undefined Protocol)', () => {
      expect(PiRC100Validator.canonicalize(null as any)).toBe("null");
      expect(PiRC100Validator.canonicalize(undefined as any)).toBe("");
    });

    test('Test 9: Logic Branch Coverage (Numeric & Boolean Literals)', () => {
      expect(PiRC100Validator.canonicalize(true)).toBe("true");
      expect(PiRC100Validator.canonicalize(42)).toBe("42");
    });

    test('Test 10: Structural Depth Limit (Recursive Protection)', () => {
      const generateDeepNest = (level: number): any => 
        level <= 0 ? { leaf: true } : { branch: generateDeepNest(level - 1) };
      
      // Targeting MAX_DEPTH = 32
      expect(() => PiRC100Validator.canonicalize(generateDeepNest(35))).toThrow("MAX_DEPTH_REACHED");
    });

    test('Test 11: SecurityManager Empty Payload Guard', () => {
      expect(SecurityManager.generatePEPProof({} as any).signature).toBe("");
    });

    /**
     * @target SecurityManager.ts:Line 43 (Catch Block)
     * Utilizes Fault Injection to simulate system-level failure during signing.
     */
    test('Test 12: SecurityManager Internal Catch Recovery (Line 43)', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      SecurityManager.setFaultInjection(true); // Trigger simulated failure
      
      const result = SecurityManager.generatePEPProof({ data: "valid" });
      expect(result.signature).toBe(""); // Ensure fail-soft returns empty signature
      
      SecurityManager.setFaultInjection(false);
      spy.mockRestore();
    });

    /**
     * @target PiRC100Validator.ts:Line 83 (Catch Block)
     * Validates protocol-level error logging on canonicalization failure.
     */
    test('Test 13: Validator Protocol Error Handling (Line 83)', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      PiRC100Validator.setFaultInjection(true); 
      
      expect(() => PiRC100Validator.canonicalize({ key: "value" })).toThrow();
      expect(spy).toHaveBeenCalled(); // Verify console.error was triggered
      
      PiRC100Validator.setFaultInjection(false);
      spy.mockRestore();
    });

    test('Test 14: Integrity Checker Null-Input Safety', () => {
      expect(PiRC100Validator.verifyIntegrity(null as any, "secret-key")).toBeNull();
    });

    /**
     * @target PiRC100Validator.ts:Line 119 (Integrity Exception Path)
     */
    test('Test 15: Integrity Internal Failure Recovery (Line 119)', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      PiRC100Validator.setFaultInjection(true);
      
      const result = PiRC100Validator.verifyIntegrity({ auth: true }, "secret");
      expect(result).toBeNull();
      
      PiRC100Validator.setFaultInjection(false);
      spy.mockRestore();
    });

    /**
     * @target PiRC100Validator.ts:Line 103 (Deterministic Hash Exception Path)
     */
    test('Test 16: Deterministic Hash Fault Tolerance (Line 103)', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      PiRC100Validator.setFaultInjection(true);
      
      expect(PiRC100Validator.generateDeterministicHash({ data: 1 })).toBe("");
      
      PiRC100Validator.setFaultInjection(false);
      spy.mockRestore();
    });

    test('Test 17: PEPProof End-to-End Success Path', () => {
      const payload = { active: true, id: "X-001" };
      const proof = SecurityManager.generatePEPProof(payload);
      const isValid = SecurityManager.verifyPEPProof(payload, proof.signature, proof.version);
      expect(isValid).toBe(true);
    });

    test('Test 18: PEPProof Signature Integrity Guard', () => {
      const payload = { active: true };
      const proof = SecurityManager.generatePEPProof(payload);
      const isValid = SecurityManager.verifyPEPProof(payload, "forged_signature", proof.version);
      expect(isValid).toBe(false);
    });

    test('Test 19: Protocol Version Compliance Guard', () => {
      const payload = { active: true };
      const proof = SecurityManager.generatePEPProof(payload);
      const isValid = SecurityManager.verifyPEPProof(payload, proof.signature, 999); // Future/Invalid version
      expect(isValid).toBe(false);
    });

    test('Test 20: Array and String Canonicalization Coverage', () => {
      expect(PiRC100Validator.canonicalize([undefined, 1])).toBe("[null,1]");
      expect(PiRC100Validator.canonicalize("EslaM-X")).toBe("\"EslaM-X\"");
    });
  });
});
