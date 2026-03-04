/**
 * @name SigmoidTierLogicTests
 * @description Unit tests for validating the non-linear allocation curves.
 * Ensures precision in tier transitions and resistance to "Tier-Farming".
 */

import { SigmoidTierLogic } from '../src/SigmoidTierLogic';

describe('Sigmoid Tier Transition Logic', () => {
  
  // Accessing the static method from the class
  const calc = SigmoidTierLogic.calculateSigmoidTier;

  test('should return near 10% discount for maximum engagement (Score 100)', () => {
    const result = calc(100);
    // Verified against L=10 asymptote
    expect(result).toBeCloseTo(9.9, 1); 
  });

  test('should return near 0% for minimum engagement (Score 0)', () => {
    const result = calc(0);
    // Ensuring high-friction at early engagement stages
    expect(result).toBeLessThan(1.0); 
  });

  test('should provide a smooth transition at the midpoint (Score 50)', () => {
    const result = calc(50);
    // In a standard sigmoid, the midpoint (x0) should return L/2
    expect(result).toBeCloseTo(5.0, 1);
  });

  test('should prevent "Tier-Farming" by ensuring non-linear increments', () => {
    const scoreA = 30;
    const scoreB = 31;
    const scoreC = 80;
    const scoreD = 81;

    const lowEndDiff = calc(scoreB) - calc(scoreA);
    const highEndDiff = calc(scoreD) - calc(scoreC);

    // In a non-linear curve, the rate of change is never constant
    expect(lowEndDiff).not.toEqual(highEndDiff);
    expect(lowEndDiff).toBeGreaterThan(0);
  });
});
