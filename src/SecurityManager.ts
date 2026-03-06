/**
 * @class SecurityManager
 * @description 
 * Orchestrates the Backend Key Registration & Rotation Model for PiRC1.
 * Implements cryptographic shielding for PEP (Programmable Engagement Proof) 
 * to ensure resilience against key exfiltration and automated Sybil attacks.
 * * Integrated with the PiRC-100 Deterministic Validation Engine (RFC 8785).
 */

import { createHmac, randomBytes } from 'crypto';
import { PiRC100Validator } from './core/PiRC100Validator';

export class SecurityManager {
  private static currentKey: string = "";
  private static keyVersion: number = 0;
  private static lastRotation: number = Date.now();

  /**
   * @method rotateKeys
   * @description Executes periodic HMAC key rotation to minimize the cryptographic attack surface.
   * Adheres to the "Governance-minimized attack surface" principle by ensuring 
   * temporal key isolation.
   */
  public static rotateKeys(): void {
    // Generate a cryptographically secure 256-bit hexadecimal key
    this.currentKey = randomBytes(32).toString('hex');
    this.keyVersion += 1;
    this.lastRotation = Date.now();
    
    console.log(`[PiRC1 Security] Cryptographic Key Rotated. Active Version: ${this.keyVersion}`);
  }

  /**
   * @method generatePEPProof
   * @description Generates a HMAC-SHA256 signature for verifiable engagement auditing.
   * Enforces RFC 8785 Canonicalization to guarantee signature consistency across 
   * heterogeneous distributed node environments.
   * * @param {object} payload - The transaction or engagement data structure.
   * @returns {Object} { signature: string, version: number } - The authenticated proof and key metadata.
   */
  public static generatePEPProof(payload: object): { signature: string; version: number } {
    if (!this.currentKey) this.rotateKeys();

    /** * Transition from standard JSON.stringify to RFC 8785 Canonicalization.
     * Prevents hash divergence caused by lexicographical key reordering in JS engines.
     */
    const canonicalData = PiRC100Validator.canonicalize(payload);
    
    const hmac = createHmac('sha256', this.currentKey);
    const signature = hmac.update(canonicalData).digest('hex');

    return {
      signature,
      version: this.keyVersion
    };
  }

  /**
   * @method verifyPEPProof
   * @description Performs deterministic cryptographic validation of incoming engagement proofs.
   * Cross-references signatures against the active key version using the canonical data format.
   * * @param {object} payload - The data structure to be validated.
   * @param {string} signature - The external signature to verify.
   * @param {number} version - The key version used for the original signature.
   * @returns {boolean} - Returns true if the proof is cryptographically valid and current.
   */
  public static verifyPEPProof(payload: object, signature: string, version: number): boolean {
    // Fail-fast mechanism for version mismatch to optimize computational resources
    if (version !== this.keyVersion) return false;

    // Re-generate signature using the identical canonical logic for exact-match comparison
    const expectedSignature = this.generatePEPProof(payload).signature;
    return signature === expectedSignature;
  }
}
