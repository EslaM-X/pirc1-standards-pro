/** * @name JestConfig (Production-Hardened)
 * @description Configuration for validating the PiRC1-Protocol.
 * Ensures strict TypeScript execution and comprehensive coverage reporting.
 */

module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  verbose: true,
  collectCoverage: true,
  coverageDirectory: 'coverage',
  coverageThreshold: {
    global: {
      branches: 95,
      functions: 100,
      lines: 98,
      statements: 98
    }
  },
  moduleFileExtensions: ['ts', 'js', 'json', 'node'],
  testPathIgnorePatterns: ['/node_modules/', '/dist/'],
  transform: {
    '^.+\\.ts$': ['ts-jest', {
      tsconfig: 'tsconfig.json',
      isolatedModules: true
    }]
  },
  displayName: {
    name: 'PIRC1-INTEGRITY-SUITE',
    color: 'blue'
  }
};
