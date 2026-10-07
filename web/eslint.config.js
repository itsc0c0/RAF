// ESLint flat config for the R$F web workbench.
import js from '@eslint/js';
import { defineConfig, globalIgnores } from 'eslint/config';
import reactHooks from 'eslint-plugin-react-hooks';
import globals from 'globals';
import tseslint from 'typescript-eslint';

/**
 * Imported security data is untrusted. These rules keep HTML injection sinks and dynamic code
 * evaluation out of the codebase entirely (React text rendering is the only rendering path).
 */
const securityRules = {
  'no-eval': 'error',
  'no-implied-eval': 'error',
  'no-new-func': 'error',
  'no-script-url': 'error',
  'no-restricted-syntax': [
    'error',
    {
      selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",
      message: 'Never inject HTML: render untrusted data as text.',
    },
    {
      selector: 'MemberExpression[property.name=/^(innerHTML|outerHTML)$/]',
      message: 'Never use innerHTML/outerHTML: render untrusted data as text.',
    },
    {
      selector: 'CallExpression[callee.property.name=/^(insertAdjacentHTML|createContextualFragment)$/]',
      message: 'Never parse HTML strings at runtime.',
    },
    {
      selector: "CallExpression[callee.object.name='document'][callee.property.name=/^(write|writeln)$/]",
      message: 'document.write is forbidden.',
    },
  ],
};

export default defineConfig([
  globalIgnores(['dist', 'coverage', 'node_modules']),
  {
    files: ['**/*.{ts,tsx}'],
    extends: [
      js.configs.recommended,
      tseslint.configs.recommendedTypeChecked,
      reactHooks.configs.flat['recommended-latest'],
    ],
    languageOptions: {
      ecmaVersion: 2022,
      globals: globals.browser,
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      ...securityRules,
      eqeqeq: ['error', 'smart'],
      'no-console': ['error', { allow: ['warn', 'error'] }],
      '@typescript-eslint/consistent-type-imports': ['error', { fixStyle: 'inline-type-imports' }],
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
      '@typescript-eslint/no-misused-promises': ['error', { checksVoidReturn: { attributes: false } }],
    },
  },
  {
    files: ['src/**/*.test.{ts,tsx}', 'src/test/**/*.{ts,tsx}'],
    rules: {
      '@typescript-eslint/no-non-null-assertion': 'off',
      '@typescript-eslint/unbound-method': 'off',
      // Tests feed hostile payloads (javascript: URLs) to prove they are neutralized.
      'no-script-url': 'off',
    },
  },
  {
    files: ['*.js'],
    extends: [js.configs.recommended],
    languageOptions: { ecmaVersion: 2022, sourceType: 'module', globals: globals.node },
    rules: securityRules,
  },
  {
    files: ['public/**/*.js'],
    extends: [js.configs.recommended],
    languageOptions: { ecmaVersion: 2022, sourceType: 'script', globals: globals.browser },
    rules: securityRules,
  },
]);
