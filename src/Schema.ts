/**
 * @name PEPSchema
 * @description 
 * Defines the Minimal Canonical PEP Schema for the PiRC1 Standard.
 * This establishes the serialization rules and data structures 
 * required for deterministic validation across the ecosystem.
 */

export interface IEngagementPayload {
  uid: string;              // KYC-verified, migrated Mainnet user ID
  action_type: string;      // Type of engagement (e.g., 'purchase', 'vote', 'post')
  timestamp: number;        // Unix timestamp for deterministic ordering
  app_id: string;           // Unique identifier for the dApp
  metadata: {
    weight: number;         // Assigned weight for the specific action
    p_floor_min: number;    // Price floor constraint at the time of action
  };
}

export interface IVerifiableProof {
  payload: IEngagementPayload;
  signature: string;        // HMAC-SHA256 signature from SecurityManager
  key_version: number;      // Current active key version for rotation tracking
}

export class SchemaValidator {
  /**
   * @name validateSchema
   * @description Ensures that incoming dApp reporting aligns with the PEP standard.
   * Implementation of "Deterministic validation standards".
   */
  public static validate(proof: IVerifiableProof): boolean {
    // 1. Structural Check
    if (!proof.payload || !proof.signature || typeof proof.key_version !== 'number') {
      return false;
    }

    // 2. Logic Check: Ensure weight is within normalized constraints [0, 1]
    if (proof.payload.metadata.weight < 0 || proof.payload.metadata.weight > 1) {
      return false;
    }

    return true;
  }
}

