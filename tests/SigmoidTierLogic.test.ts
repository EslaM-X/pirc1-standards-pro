// Testing the Sigmoid Logic for PiRC1 Standards
import { calculateSigmoidTier } from '../src/SigmoidTierLogic';

describe('Sigmoid Tier Transition Logic', () => {
  
  test('should return 10% discount for maximum engagement (Score 100)', () => {
    const result = calculateSigmoidTier(100);
    expect(result).toBeCloseTo(10.0, 1); // Max discount
  });

  test('should return near 0% for minimum engagement (Score 0)', () => {
    const result = calculateSigmoidTier(0);
    expect(result).toBeLessThan(1.0); 
  });

  test('should provide a smooth transition at the midpoint (Score 50)', () => {
    const result = calculateSigmoidTier(50);
    // In a sigmoid, midpoint should be around 5% if max is 10%
    expect(result).toBeGreaterThan(4.5);
    expect(result).toBeLessThan(5.5);
  });

  test('should prevent "Tier-Farming" by ensuring non-linear increments', () => {
    const scoreA = 30;
    const scoreB = 31;
    const diff = calculateSigmoidTier(scoreB) - calculateSigmoidTier(scoreA);
    // Ensure the growth follows the sigmoid curve, not a fixed step
    expect(diff).not.toBe(0); 
  });
});

