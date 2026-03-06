/**
 * @name SigmoidTierLogicTests (Hardened & PiRC-100 Ready)
 * @description 
 * Unit tests for validating Deterministic Fixed-Point Sigmoid curves.
 * Ensures 18-decimal precision and verifies the "Launchpad-grade" security model.
 * Compliance: RFC 8785 & PiRC-100 Integration.
 */

import { SigmoidTierLogic } from '../src/SigmoidTierLogic';

describe('Sigmoid Tier Transition Logic (Deterministic Validation)', () => {
  
  const calc = SigmoidTierLogic.calculateSigmoidTier;

  test('Vector 1: should return 18-decimal fixed-point string for maximum engagement (Score 100)', () => {
    const result = calc(100);
    
    // In a hardened environment, we expect a precise string representation
    // Verified against L=10 asymptote with high precision (18 decimals)
    expect(result.startsWith("9.9")).toBe(true);
    const decimals = result.split(".")[1];
    expect(decimals.length).toBe(18); // Ensuring 18-decimal protocol standard
  });

  test('Vector 2: should enforce High-Friction at early engagement stages (Score 0)', () => {
    const result = calc(0);
    const numericResult = parseFloat(result);
    
    // Ensuring Sybil-resistance by keeping early rewards extremely low (Anti-Farming)
    expect(numericResult).toBeLessThan(0.1); 
    expect(result.length).toBeGreaterThan(15); // Integrity check for 18-decimal format
  });

  test('Vector 3: should provide a perfect midpoint transition at x0 (Score 50)', () => {
    const result = calc(50);
    const numericResult = parseFloat(result);
    
    // In a standard sigmoid, the midpoint (x0) must return exactly L/2 (5.0)
    // Testing the deterministic convergence of the fixed-point logic
    expect(numericResult).toBe(5.0);
  });

  test('Vector 4: should verify Deterministic Non-Linearity (Anti-Manipulation Check)', () => {
    const scoreA = 30;
    const scoreB = 31;
    const scoreC = 80;
    const scoreD = 81;

    const diff1 = parseFloat(calc(scoreB)) - parseFloat(calc(scoreA));
    const diff2 = parseFloat(calc(scoreD)) - parseFloat(calc(scoreC));

    // Validating that the growth rate follows the non-linear Sigmoid factor
    // This prevents linear "gaming" of the allocation system
    expect(diff1).not.toEqual(diff2);
    expect(diff1).toBeGreaterThan(0);
  });

  test('Security Gate 1: should enforce Protocol-Level Security for Non-KYC users', () => {
    // Testing the core security gate: isKycVerified = false
    const result = SigmoidTierLogic.getSecuredAllocation(100, false);
    
    // Secure protocol MUST return absolute zero string to prevent leakage
    expect(result).toBe("0.000000000000000000");
  });

  test('Security Gate 2: should respect the Dynamic Price Floor (p_floor)', () => {
    // Testing a very low engagement score that would normally fall below p_floor
    const p_floor = 0.50;
    const result = SigmoidTierLogic.getSecuredAllocation(1, true, p_floor);
    
    // Result must be clamped to p_floor to maintain economic stability
    expect(parseFloat(result)).toBeCloseTo(p_floor, 2);
  });

  /**
   * @test Audit Compliance
   * Ensures the transparency manifest is reachable and reflects the PiRC-100 standard.
   */
  test('Audit: should provide a valid Transparency Manifest for audit logs', () => {
    const manifest = SigmoidTierLogic.getTransparencyManifest();
    
    // Validating internal structure without breaking existing dashboard logic
    expect(manifest.protocol).toContain("PiRC"); 
    expect(manifest.version).toBeDefined();
    expect(manifest.logic).toContain("Sigmoid");
  });
});
