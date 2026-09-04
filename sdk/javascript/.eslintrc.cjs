module.exports = {
  root: true,
  env: {
    browser: true,
    es2022: true,
    node: true,
  },
  extends: [
    'eslint:recommended',
    'plugin:@typescript-eslint/recommended',
    'plugin:@typescript-eslint/recommended-requiring-type-checking',
    'plugin:@typescript-eslint/strict',
    'prettier',
  ],
  parser: '@typescript-eslint/parser',
  parserOptions: {
    ecmaVersion: 'latest',
    sourceType: 'module',
    project: ['./tsconfig.json'],
    tsconfigRootDir: __dirname,
  },
  plugins: ['@typescript-eslint'],
  rules: {
    // TypeScript-specific rules
    '@typescript-eslint/explicit-function-return-type': 'off',
    '@typescript-eslint/explicit-module-boundary-types': 'off',
    '@typescript-eslint/no-explicit-any': 'error',
    '@typescript-eslint/no-unused-vars': [
      'error',
      {
        argsIgnorePattern: '^_',
        varsIgnorePattern: '^_',
      },
    ],
    '@typescript-eslint/prefer-nullish-coalescing': 'error',
    '@typescript-eslint/prefer-optional-chain': 'error',
    '@typescript-eslint/strict-boolean-expressions': 'off',
    '@typescript-eslint/no-non-null-assertion': 'error',
    '@typescript-eslint/consistent-type-imports': [
      'error',
      {
        prefer: 'type-imports',
        fixStyle: 'inline-type-imports',
      },
    ],
    '@typescript-eslint/consistent-type-exports': [
      'error',
      {
        fixMixedExportsWithInlineTypeSpecifier: true,
      },
    ],

    // General rules
    'no-console': ['warn', { allow: ['warn', 'error'] }],
    'prefer-const': 'error',
    'no-var': 'error',
    eqeqeq: ['error', 'always'],
    curly: ['error', 'all'],
  },
  overrides: [
    {
      // `unbound-method` exists to catch `this`-binding loss when a method is
      // passed somewhere and later invoked detached. The assertion style this
      // suite is built on —
      //
      //     expect(typeof client.kv.get).toBe('function');
      //     expect(client.secrets).toBeInstanceOf(QuicBaaSSecretsService);
      //
      // — only READS a property: there is no call, no receiver, and no
      // reachable defect for the rule to have found. It fired 417 times across
      // the test suite the moment those files became visible to typed linting
      // (#247), every one of them on that construct.
      //
      // This is a known false positive, NOT tolerated debt: rewriting 417
      // assertions to bind methods would make the suite harder to read in
      // order to satisfy a rule that has nothing true to say about them. It
      // stays fully enforced everywhere outside test files, where a detached
      // method reference is a real risk.
      files: ['**/__tests__/**/*.ts', '**/*.test.ts', '**/*.spec.ts'],
      rules: {
        '@typescript-eslint/unbound-method': 'off',
      },
    },
  ],
  ignorePatterns: ['dist', 'node_modules', '*.js', '*.cjs'],
};
