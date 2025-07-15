const js = require('@eslint/js');

module.exports = [
  {
    ...js.configs.recommended,
    languageOptions: {
      ecmaVersion: 2018,
      globals: {
        ...require('globals').node,
        ...require('globals').es6,
        ...require('globals').mocha,
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
