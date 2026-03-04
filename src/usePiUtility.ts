/**
 * @name usePiUtility
 * @description Standardized React Hook for the PiRC1 Protocol.
 * Implements the "Deterministic Validation Standards" for cross-dApp interoperability.
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
   * @name reportActivity
   * @description Handles the formal reporting of engagement using the PEP Schema.
   * Ensures that data is serialized correctly before transmission to the backend.
   */
  const reportActivity = useCallback(async (
    payload: IEngagementPayload, 
    signature: string, 
    keyVersion: number
  ) => {
    setIsVerifying(true);
    
    try {
      // 1. Construct the Verifiable Proof based on the Canonical Schema
      const proof: IVerifiableProof = {
        payload,
        signature,
        key_version: keyVersion
      };

      console.log(`[PiRC1-Protocol] Initiating PEP Verification for App: ${config.appId}`);

      /**
       * @implementation Integration with Pi SDK / Backend
       * This follows the "Launchpad-grade security" model proposed for the ecosystem.
       */
      const response = await fetch('/api/pirc1/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(proof) // Deterministic Serialization
      });

      if (!response.ok) throw new Error("Verification Rejected by Protocol");

      const result = await response.json();
      setLastProof(proof);
      
      return { 
        success: true, 
        integrity_hash: signature, 
        timestamp: Date.now() 
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
    protocolVersion: "v2.0-Hardened" 
  };
};
