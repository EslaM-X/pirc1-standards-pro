/**
 * @name PEPSchema
 * @description 
 * Defines the Minimal Canonical PEP Schema for the PiRC1 and PiRC-100 Standards.
 * Establishes the core data structures and serialization rules required for 
 * deterministic validation and RFC 8785 compliance.
 * @author EslaM-X | Lead Technical Architect
 */

export interface IEngagementPayload {
  uid: string;              // KYC-verified, migrated Mainnet user ID
  action_type: string;      // Type of engagement (e.g., 'purchase', 'vote', 'post')
  timestamp: number;        // High-precision Unix timestamp for deterministic ordering
  app_id: string;           // Unique identifier for the dApp (e.g., 'MAPLYPI')
  metadata: {
    weight: number;         // Assigned weight for the specific action [0, 1]
    p_floor_min: number;    // Dynamic price floor constraint at the time of action
  };
}

export interface IVerifiableProof {
  payload: IEngagementPayload;
  signature: string;        // HMAC-SHA256 signature generated via RFC 8785 Canonicalization
  key_version: number;      // Current active key version for cryptographic rotation tracking
}

export class SchemaValidator {
  /**
   * @method validate
   * @description 
   * Formally validates that incoming dApp reports align with the PEP & PiRC-100 standards.
   * Ensures structural integrity before passing the payload to the cryptographic layer.
   * @param {IVerifiableProof} proof - The verifiable engagement proof.
   * @returns {boolean} - Validation result.
   */
  public static validate(proof: IVerifiableProof): boolean {
    // 1. Structural Integrity Check: Ensure all mandatory fields exist
    if (!proof.payload || !proof.signature || typeof proof.key_version !== 'number') {
      console.warn("[PiRC1 Schema] Structural validation failed: Missing mandatory fields.");
      return false;
    }

    // 2. Logic & Weight Bounding: Ensure weights are within normalized constraints [0, 1]
    // Implementation of "Strict-Normalized" utility framework.
    const { weight } = proof.payload.metadata;
    if (typeof weight !== 'number' || weight < 0 || weight > 1) {
      console.warn(`[PiRC1 Schema] Logic breach: Weight ${weight} out of normalized bounds.`);
      return false;
    }

    // 3. Metadata Integrity
    if (typeof proof.payload.metadata.p_floor_min !== 'number') {
      return false;
    }

    return true;
  }
}
