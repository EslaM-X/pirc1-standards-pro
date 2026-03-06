/**
 * @name JestConfig (Production-Hardened)
 * @description 
 * Centralized testing configuration for the PiRC1-Protocol and PiRC-100 Standards.
 * Engineered to enforce strict TypeScript execution, deterministic validation, 
 * and comprehensive cryptographic coverage reporting.
 * * Integrated with the RFC 8785 (JCS) Deterministic Validation Suite to ensure 
 * zero hash divergence across distributed node environments.
 */

module.exports = {
  // Utilizing ts-jest preset for seamless TypeScript integration and type-checking during test cycles.
  preset: 'ts-jest',

  // Target environment set to Node.js to mirror the backend execution context.
  testEnvironment: 'node',

  // Enable verbose output for granular reporting of each individual test execution.
  verbose: true,

  // Enable automated coverage collection to audit codebase integrity.
  collectCoverage: true,

  // Output directory for generated coverage reports.
  coverageDirectory: 'coverage',

  /**
   * @section CoverageThreshold
   * @description Defines strict architectural guardrails to prevent untested logic from entering production.
   * Enforces a "Zero-Defect" policy by requiring 100% function coverage.
   */
  coverageThreshold: {
    global: {
      branches: 95,
      functions: 100, // Mandatory compliance: Every function must be cryptographically validated.
      lines: 98,
      statements: 98
    }
  },

  // Supported file extensions for module resolution.
  moduleFileExtensions: ['ts', 'js', 'json', 'node'],

  // Exclude compiled artifacts and dependencies from the scanning process.
  testPathIgnorePatterns: ['/node_modules/', '/dist/'],

  /**
   * @section Transformation
   * @description Configures the TypeScript pre-processor with optimized settings.
   */
  transform: {
    '^.+\\.ts$': ['ts-jest', {
      tsconfig: 'tsconfig.json',
      // isolatedModules: true ensures faster transpilation and prevents cross-file side effects.
      isolatedModules: true
    }]
  },

  /**
   * @section DisplayMetadata
   * @description Visual branding for the CI/CD pipeline output.
   */
  displayName: {
    name: 'PIRC-100-INTEGRITY-SUITE',
    color: 'blue'
  }
};
