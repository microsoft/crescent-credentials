import eslintLove from 'eslint-config-love'
import stylistic from '@stylistic/eslint-plugin'

/*
    eslint-config-love provides comprehensive rules for JavaScript, TypeScript, Node.js, import management, and promises.

    For .js files, some TypeScript-specific rules are disabled as they don't apply.

    The 'stylistic' plugin is used for style customization with:
    - 4-space indentation
    - No trailing commas
*/

/*
    TypeScript rules that don't apply to JavaScript.
    This is a partial list—add more as needed.
*/
const tsRuleExceptions = {
    '@typescript-eslint/explicit-function-return-type': 'off',
    '@typescript-eslint/no-unsafe-argument': 'off',
    '@typescript-eslint/no-unsafe-function-type': 'off'
}

export default [
    {
        ignores: ['dist']
    },
    {
        files: ['*.config.js'],
        ...eslintLove,
        rules: {
            ...eslintLove.rules,
            ...tsRuleExceptions
        }
    },
    {
        files: ['src/**/*.ts'],
        ...eslintLove,
        /*
            @types/chrome introduced deprecation warnings for
            chrome.browser, chrome.serial, and chrome.socket using the '@deprecated' JSDoc tag.
            However, due to a bug, these warnings are incorrectly applied to all chrome.* APIs.
            See: https:github.com/typescript-eslint/typescript-eslint/issues/9902
            We are disabling the deprecation warnings for now.
            Delete the entire 'rules' object below when fixed.
         */
        rules: {
            ...eslintLove.rules,
            '@typescript-eslint/no-deprecated': 'off'
        }

    },
    stylistic.configs.customize({
        // eslint-disable-next-line @typescript-eslint/no-magic-numbers
        indent: 4,
        commaDangle: 'never'
    })
]
