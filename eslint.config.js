import js from '@eslint/js';
import globals from 'globals';

export default [
  {
    ...js.configs.recommended,
    languageOptions: {
      ecmaVersion: 2024,
      sourceType: 'module',
      globals: {
        ...globals.node,
        ...globals.es6,
        ...globals.mocha,
      },
    },
    rules: {
      'no-useless-escape': 'warn',
      'no-unused-vars': [
        'error',
        {
          vars: 'all',
          args: 'after-used',
          ignoreRestSiblings: true,
        },
      ],
      'no-console': 'off',
      'linebreak-style': ['error', 'unix'],
    },
  },
  {
    ignores: [
      'CHANGELOG.md',
      'coverage/**',
      '.nyc_output/**',
      'docs/**',
      '.cache/**',
      'node_modules/**',
    ],
  },
];
