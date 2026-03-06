import { PiRC100Validator } from '../src/core/PiRC100Validator';
import { SecurityManager } from '../src/SecurityManager';
import referenceVectors from './vectors/pirc100-reference.json';

/**
 * @file RFC8785_Vectors.test.ts
 * @description 
 * FINAL AUDIT VERSION - ZERO REGRESSION.
 * Engineered by EslaM-X to reach 100% Path Exhaustion.
 * This version forces internal catch-blocks 43 and 63 to execute.
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

    test('Gate 2: Circular Reference Interception', () => {
      const nodeA: any = { name: "NodeA" };
      const nodeB: any = { name: "NodeB" };
      nodeA.link = nodeB;
      nodeB.link = nodeA; 
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      expect(() => PiRC100Validator.canonicalize(nodeA)).toThrow(); 
      spy.mockRestore();
    });

    /**
     * @target SecurityManager.ts:43
     * Forces the internal catch block by passing an object that 
     * cannot be processed by the internal cryptographic logic.
     */
    test('Gate 3: SecurityManager Internal Error Coverage', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      
      // Line 39 coverage
      expect(SecurityManager.generatePEPProof({} as any).signature).toBe("");

      // Line 43 coverage: Forced Internal Error
      const fatal: any = { 
        toJSON: () => { throw new Error("INTERNAL_FATAL"); } 
      };
      expect(SecurityManager.generatePEPProof(fatal).signature).toBe("");
      
      spy.mockRestore();
    });

    test('Gate 4: verifyPEPProof Logical Pathing', () => {
      SecurityManager.rotateKeys();
      const payload = { auth: "valid" };
      const proof = SecurityManager.generatePEPProof(payload);
      expect(SecurityManager.verifyPEPProof(payload, proof.signature, proof.version)).toBe(true);
      expect(SecurityManager.verifyPEPProof(payload, "", proof.version)).toBe(false);
    });

    test('Gate 7: Integrity Verification Edge Cases', () => {
      expect(PiRC100Validator.verifyIntegrity(null as any, "secret")).toBeNull();
      expect(typeof PiRC100Validator.verifyIntegrity({ a: 1 }, "secret")).toBe('string');
    });

    /**
     * @target PiRC100Validator.ts:63 & 83
     * The "Recursive Bomb" strategy to ensure the map function fails 
     * during the sorting/processing phase.
     */
    test('Gate 8: Absolute Path Exhaustion (Line 63 & 83)', () => {
      const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
      
      // 1. Depth Limit (Line 34)
      const buildDeep = (l: number): any => (l <= 0 ? { x: 1 } : { n: buildDeep(l - 1) });
      expect(() => PiRC100Validator.canonicalize(buildDeep(35))).toThrow();

      // 2. Forced Mapping Catch (Line 63 & 83)
      const poison = {
        get bomb() { throw new Error("MAPPING_EXCEPTION"); }
      };
      // Object.defineProperty ensures it's seen during Object.keys loop
      Object.defineProperty(poison, 'bomb', { enumerable: true });
      
      expect(() => PiRC100Validator.canonicalize(poison)).toThrow();

      // 3. Integrity Catch (Line 103)
      const circ: any = { id: 1 }; circ.self = circ; 
      expect(PiRC100Validator.verifyIntegrity(circ, "secret")).toBeNull();
      expect(PiRC100Validator.generateDeterministicHash(circ)).toBe("");

      // 4. Array Normalization
      expect(PiRC100Validator.canonicalize([undefined])).toBe("[null]");
      
      spy.mockRestore();
    });
  });
});
