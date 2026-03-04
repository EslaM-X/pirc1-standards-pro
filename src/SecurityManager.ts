/**
 * @name SecurityManager
 * @description 
 * Implements the Backend Key Registration & Rotation Model as part of PiRC1.
 * Ensures that PEP (Programmable Engagement Proof) remains resilient 
 * against key leakage and automated bot manipulation.
 */

import { createHmac, randomBytes } from 'crypto';

export class SecurityManager {
  private static currentKey: string = "";
  private static keyVersion: number = 0;
  private static lastRotation: number = Date.now();

  /**
   * @name rotateKeys
   * @description Periodically rotates the HMAC signing keys to minimize attack surface.
   * Implementation of "Governance-minimized attack surface".
   */
  public static rotateKeys(): void {
    this.currentKey = randomBytes(32).toString('hex');
    this.keyVersion += 1;
    this.lastRotation = Date.now();
    
    console.log(`[PiRC1 Security] Key Rotated. Version: ${this.keyVersion}`);
  }

  /**
   * @name generatePEPProof
   * @description Creates a HMAC-SHA256 signed payload for verifiable engagement.
   * Ensures Launchpad-grade security for dApp-to-Backend communication.
   */
  public static generatePEPProof(payload: object): { signature: string; version: number } {
    if (!this.currentKey) this.rotateKeys();

    const data = JSON.stringify(payload);
    const hmac = createHmac('sha256', this.currentKey);
    const signature = hmac.update(data).digest('hex');

    return {
      signature,
      version: this.keyVersion
    };
  }

  /**
   * @name verifyPEPProof
   * @description Deterministic validation of engagement proofs.
   * Only accepts signatures from the current active key version.
   */
  public static verifyPEPProof(payload: object, signature: string, version: number): boolean {
    if (version !== this.keyVersion) return false;

    const expectedSignature = this.generatePEPProof(payload).signature;
    return signature === expectedSignature;
  }
}

