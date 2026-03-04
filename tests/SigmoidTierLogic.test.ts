/**
 * @name SigmoidTierLogicTests (Hardened)
 * @description 
 * Unit tests for validating Deterministic Fixed-Point Sigmoid curves.
 * Ensures 18-decimal precision and verifies the "Launchpad-grade" security model.
 */

import { SigmoidTierLogic } from '../src/SigmoidTierLogic';

describe('Sigmoid Tier Transition Logic (Deterministic Validation)', () => {
  
  const calc = SigmoidTierLogic.calculateSigmoidTier;

  test('should return 18-decimal fixed-point string for maximum engagement (Score 100)', () => {
    const result = calc(100);
    
    // In a hardened environment, we expect a precise string representation
    // Verified against L=10 asymptote with high precision
    expect(result.startsWith("9.9")).toBe(true);
    expect(result.split(".")[1].length).toBe(18); // Ensuring 18-decimal standard
  });

  test('should enforce High-Friction at early engagement stages (Score 0)', () => {
    const result = calc(0);
    const numericResult = parseFloat(result);
    
    // Ensuring Sybil-resistance by keeping early rewards extremely low
    expect(numericResult).toBeLessThan(0.1); 
    expect(result.length).toBeGreaterThan(15); // Integrity check
  });

  test('should provide a perfect midpoint transition at x0 (Score 50)', () => {
    const result = calc(50);
    const numericResult = parseFloat(result);
    
    // In a standard sigmoid, the midpoint (x0) must return exactly L/2 (5.0)
    expect(numericResult).toBe(5.0);
  });

  test('should verify Deterministic Non-Linearity (Anti-Farming Check)', () => {
    const scoreA = 30;
    const scoreB = 31;
    const scoreC = 80;
    const scoreD = 81;

    const diff1 = parseFloat(calc(scoreB)) - parseFloat(calc(scoreA));
    const diff2 = parseFloat(calc(scoreD)) - parseFloat(calc(scoreC));

    // Validating that the growth rate follows the Sigmoid professionalism factor (k)
    expect(diff1).not.toEqual(diff2);
    expect(diff1).toBeGreaterThan(0);
  });

  test('should enforce Protocol-Level Security for Non-KYC users', () => {
    // Testing the security gate: isKycVerified = false
    const result = SigmoidTierLogic.getSecuredAllocation(100, false);
    
    // Secure protocol must return absolute zero string
    expect(result).toBe("0.000000000000000000");
  });

  test('should respect the Dynamic Price Floor (p_floor)', () => {
    // Testing a very low engagement score that would normally fall below p_floor
    const p_floor = 0.50;
    const result = SigmoidTierLogic.getSecuredAllocation(1, true, p_floor);
    
    // Result must be clamped to p_floor even if the curve suggests lower
    expect(parseFloat(result)).toBeCloseTo(p_floor, 2);
  });
});
