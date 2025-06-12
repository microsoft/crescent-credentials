import commonjs from '@rollup/plugin-commonjs'
import json from '@rollup/plugin-json'
import resolve from '@rollup/plugin-node-resolve'
import terser from '@rollup/plugin-terser'
import 'dotenv/config'
import path, { dirname } from 'path'
import copy from 'rollup-plugin-copy'
import typescript from 'rollup-plugin-typescript2'
import { fileURLToPath } from 'url'
import dotenv from 'rollup-plugin-dotenv'

function getDirname (url) {
  return dirname(fileURLToPath(url))
}

const __dirname = getDirname(import.meta.url)

/*
  - Build 5 bundles in the dist/chrome folder with supporting files:
    - background.js
    - content.js
    - popup.js

  - Copy the dist/chrome folder to dist/firefox

  - Copy the browser-specific manifest.json files to their respective folders

  - Set the desired manifest version in the .env file

  Occasionally, when running rollup, you may get an error like this from rollup-plugin-typescript2:
  [!] (plugin rpt2) Error: EPERM: operation not permitted, rename

  Re-running rollup seems to fix it.
  I did not see a cause/solution at https://github.com/ezolenko/rollup-plugin-typescript2/issues

*/
const isDebug = process.env.NODE_ENV !== 'production'

const COPYRIGHT = `/*!\n*  Copyright (c) Microsoft Corporation.\n*  Licensed under the MIT license.\n*/`

let crescentDir = (path.dirname(fileURLToPath(import.meta.url)) + '/node_modules/crescent').replace(/\\/g, '/')

/*
  Common output options for all bundles
*/
const commonOutput = {
  format: 'esm',
  sourcemap: isDebug,
  // put a copyright banner at the top of the bundle
  banner: isDebug ? undefined : COPYRIGHT
}

const watch = {
  include: ['src/**', 'public/**', 'manifests/**', '.env'],
  clearScreen: true
}

/*
  Common plugin options for all bundles
  - replace variables from .env with their values since the browser cannot access .env
  - bundle node modules (resolve)
  - convert commonjs modules to esm (commonjs)
  - minify the production bundle (terser)
  - compile typescript to javascript (typescript)
*/
const commonPlugins = [
  dotenv(),
  json(),
  resolve({ browser: true }),
  commonjs(),
  // minify the bundle in production
  !isDebug
  && terser({
    output: {
      comments: function (node, comment) {
        // remove all comment except those starting with '!'
        return comment.value.startsWith('!')
      }
    }
  }),
  typescript({
    tsconfig: 'tsconfig.build.json'
  }),
  {
    name: 'watch-json',
    buildStart () {
      // these paths must also be included in the watch.include array above
      this.addWatchFile(path.resolve(__dirname, '.env'))
      this.addWatchFile(path.resolve(__dirname, 'manifests/manifest.chrome.json'))
      this.addWatchFile(path.resolve(__dirname, 'manifests/manifest.firefox.json'))
      this.addWatchFile(path.resolve(__dirname, 'public/popup.html'))
      this.addWatchFile(path.resolve(__dirname, 'public/popup.css'))
    }
  }
]

/*
  Common error handler for all bundles
  - suppress circular dependency warnings in the production bundle
*/
const commonWarningHandler = (warning, warn) => {
  // suppress circular dependency warnings in production
  if (warning.code === 'CIRCULAR_DEPENDENCY' && !isDebug) return
  warn(warning)
}

/*
  background.js
*/
const background = {
  input: 'src/background.ts',
  treeshake: {
    moduleSideEffects: (id) => {
      return ['src/verifier.ts', 'src/clientHelper.ts'].some(file => id.replace(/\\/g, '/').endsWith(file))
    }
  },
  output: {
    dir: 'dist/chrome',
    ...commonOutput
  },
  watch,
  plugins: [
    ...commonPlugins
  ],
  onwarn: commonWarningHandler
}

/*
  content.js
*/
const content = {
  input: 'src/content.ts',
  treeshake: {
    moduleSideEffects: []
  },
  output: {
    file: 'dist/chrome/content.js',
    ...commonOutput,
    manualChunks: undefined,
    format: 'iife' // always iife as this code is injected into the tab and not imported
  },
  watch,
  plugins: commonPlugins,
  onwarn: commonWarningHandler
}

/*
  popup.js
*/
const popup = {
  input: ['src/popup.ts', 'src/components/toggle.ts', 'src/components/card.ts', 'src/components/collapsible.ts'],
  treeshake: {
    moduleSideEffects: []
  },
  output: {
    dir: 'dist/chrome',
    ...commonOutput
  },
  watch,
  plugins: [
    copy({
      targets: [
        { src: 'public/popup.html', dest: 'dist/chrome' },
        { src: 'public/popup.css', dest: 'dist/chrome' }
      ]
    }),
    ...commonPlugins
  ],
  onwarn: commonWarningHandler
}

/*
  When the chrome extension is built, we want to duplicate the dist/chrome folder and rename it to firefox
  Then we want to copy the browser-specific manifests to each folder
  We append this copy step to the end of the last bundle so all files are available to copy
*/
const duplicateFirefox = copy({
  targets: [
    { src: 'public/icons', dest: 'dist/chrome' },
    { src: `${crescentDir}/*.wasm`, dest: 'dist/chrome' },
    { src: 'dist/chrome', dest: 'dist', rename: 'firefox' },
    {
      src: `manifests/manifest.chrome.json`,
      dest: 'dist/chrome',
      rename: 'manifest.json'
    },
    {
      src: `manifests/manifest.firefox.json`,
      dest: 'dist/firefox',
      rename: 'manifest.json'
    }
  ],
  // ensures the copy happens after the bundle is written so all files are available to copy
  hook: 'writeBundle'
})

// append the duplicateFirefox plugin to the last bundle
popup.plugins.push(duplicateFirefox)

// the order matters here
export default [background, content, popup]
