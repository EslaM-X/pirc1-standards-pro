/**
 * @name SigmoidTierLogic
 * @description Implements dynamic, non-linear allocation tiers for the Pi Launchpad.
 * Designed to eliminate "Tier-Farming" and ensure smooth incentive transitions.
 * @formula f(x) = L / (1 + exp(-k * (x - x0)))
 */

export class SigmoidTierLogic {
  /**
   * Calculates the allocation multiplier based on engagement score.
   * @param x User engagement score (Input)
   * @param L Max allocation limit (Asymptote) - Default 10.0 for 10%
   * @param k Growth steepness (The 'Professionalism' factor)
   * @param x0 Mid-point (The inflection point)
   */
  public static calculateSigmoidTier(
    x: number,
    L: number = 10.0, 
    k: number = 0.1,
    x0: number = 50
  ): number {
    // High-precision Sigmoid Implementation
    const exponent = -k * (x - x0);
    const multiplier = L / (1 + Math.exp(exponent));
    
    // Return formatted to 4 decimal places for blockchain precision
    return parseFloat(multiplier.toFixed(4));
  }

  /**
   * Prevents Sybil manipulation by flattening the curve at low-trust scores.
   * Ensures that only KYC-verified pioneers can access the utility curve.
   */
  public static getSecuredAllocation(engagementScore: number, kycVerified: boolean): number {
    if (!kycVerified) return 0;
    return this.calculateSigmoidTier(engagementScore);
  }
}
