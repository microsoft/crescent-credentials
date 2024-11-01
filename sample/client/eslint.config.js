/*
 *  Copyright (c) Larry Joy.
 *  Licensed under the MIT license.
 */

import eslintLove from 'eslint-config-love'
import stylistic from '@stylistic/eslint-plugin'
import eslint from '@eslint/js'
import globals from 'globals'

const stylisticRecommended = stylistic.configs['recommended-flat']

const standardJsRules = {
  '@stylistic/comma-dangle': ['error', 'never'],
  '@stylistic/space-before-function-paren': ['error', 'always'],
  'no-unused-vars': ['error', { varsIgnorePattern: '^_', argsIgnorePattern: '^_', caughtErrorsIgnorePattern: '^_' }],
  '@typescript-eslint/no-unused-vars': 'off', // This rule is covered by no-unused-vars,
  '@typescript-eslint/no-deprecated': 'off'
}

export default [
  {
    ignores: ['dist']
  },
  {
    files: ['**/*.ts'],
    ...eslintLove
  },
  {
    files: ['**/*.ts'],
    ...stylisticRecommended,
    rules: {
      ...stylisticRecommended.rules,
      ...standardJsRules
    }
  },
  {
    files: ['**/*.config.js'],
    languageOptions: { globals: { ...globals.node } },
    ...stylisticRecommended,
    rules: {
      ...eslint.configs.recommended.rules,
      ...stylisticRecommended.rules,
      ...standardJsRules
    }
  }
]
