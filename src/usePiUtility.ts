/**
 * @name usePiUtility
 * @description Standardized React Hook for the PiRC1 & PiRC-100 Protocols.
 * Implements "Deterministic Validation Standards" to ensure cross-dApp interoperability.
 * Engineered for Launchpad-grade security and state-consistency.
 * @author EslaM-X | Lead Technical Architect
 */

import { useState, useCallback } from 'react';
import { IVerifiableProof, IEngagementPayload } from './Schema';

export const usePiUtility = (config: { 
  appId: string, 
  securityMode: 'PEP_HARDENED' | 'LEGACY' 
}) => {
  const [isVerifying, setIsVerifying] = useState(false);
  const [lastProof, setLastProof] = useState<IVerifiableProof | null>(null);

  /**
   * @method reportActivity
   * @description Handles the formal reporting of engagement using the PEP & RFC 8785 Schema.
   * Ensures that payload integrity is maintained during transmission to the verification layer.
   * @param {IEngagementPayload} payload - The core engagement data.
   * @param {string} signature - The HMAC-SHA256 deterministic signature.
   * @param {number} keyVersion - The active key rotation version.
   */
  const reportActivity = useCallback(async (
    payload: IEngagementPayload, 
    signature: string, 
    keyVersion: number
  ) => {
    setIsVerifying(true);
    
    try {
      /**
       * 1. Construct the Verifiable Proof.
       * Following PiRC-100 standards, the proof encapsulates the deterministic 
       * signature derived from RFC 8785 canonicalization.
       */
      const proof: IVerifiableProof = {
        payload,
        signature,
        key_version: keyVersion
      };

      console.log(`[PiRC1-Protocol] Initiating PEP Verification for App: ${config.appId}`);

      /**
       * @implementation Integration with Pi SDK / Backend
       * Adheres to the "Zero-Trust" model where the backend validates 
       * the canonical parity of the payload.
       */
      const response = await fetch('/api/pirc1/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        /**
         * Note: While JSON.stringify is used for transmission, 
         * the signature was generated using PiRC100Validator.canonicalize 
         * to ensure cross-node parity.
         */
        body: JSON.stringify(proof) 
      });

      if (!response.ok) throw new Error("Verification Rejected by Protocol Layer");

      const result = await response.json();
      setLastProof(proof);
      
      return { 
        success: true, 
        integrity_hash: signature, 
        timestamp: Date.now(),
        status: "Validated"
      };

    } catch (error) {
      console.error("[PiRC1 Security Error] Protocol Breach or Network Failure", error);
      throw error;
    } finally {
      setIsVerifying(false);
    }
  }, [config.appId]);

  return { 
    reportActivity, 
    isVerifying, 
    lastProof,
    // Upgraded protocol version to reflect PiRC-100 compliance
    protocolVersion: "v2.1-PiRC100-Hardened" 
  };
};
