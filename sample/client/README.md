# Crescent sample client browser extension

This project contains a Edge/Chrome/Firefox browser extension implementing a Crescent prover. The browser extension can interact with the [sample issuer](../issuer/README.md) to retrieve JSON Web Tokens (JWT) and present a Crescent zero-knowledge proof to the [sample verifier](../verifier/README.md), with the help of a [client helper](../client_helper/README.md) to offload expensive storage and computation.

## Setup

Make sure [node.js](https://nodejs.org/) and [npm](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm) are installed on your system; the latest Long-Term Support (LTS) version is recommended for both.

Run the install script:

`npm install`

## Build

Build the extension (4 modes):

* production build (minified w/o sourcemapping)  
`npm run build`

* debug build (no minification and sourcemapping enabled)  
`npm run build:debug`

* watch build (watches files and does debug build on save)  
`npm run build:watch`

* run the client setup script to build the crescent wasm and build the browser extension  
`./setup_client.sh`

## Show Proof Generation

The show proof can be generated in the browser extension or offloaded to the client helper service. The default is to generate the proof in the browser extension.
To do the proof generation in the client helper service, set the `CLIENT_HELPER_SHOW_PROOF=true` in the `.env` file or by setting `CLIENT_HELPER_SHOW_PROOF=true` in your environment before running the build command.

```bash
CLIENT_HELPER_SHOW_PROOF=true ./setup_client.sh
```

## Installation

Follow the side-loading instruction for your browser to load the extension:

[Edge](https://learn.microsoft.com/en-us/microsoft-edge/extensions-chromium/getting-started/extension-sideloading)  
[Chrome](https://developer.chrome.com/docs/extensions/mv3/getstarted/development-basics/#load-unpacked)  
[Firefox](https://extensionworkshop.com/documentation/develop/temporary-installation-in-firefox/)

The Edge/Chrome `manifest.json` file is located at `samples/browser-extension/dist/chrome`  
The Firefox `manifest.json` file is located at `samples/browser-extension/dist/firefox`  

### Firefox

There is a known issue when using the client extension on Firefox where the extension popup window closes immediately after opening the filepicker when importing a credential from file, preventing the import from succeeding. To work around this:  

1. Open a new tab and navigate to `about:config`.
2. Search for `ui.popup.disable_autohide` and set it to `true`.

**Note**: This change keeps the popup window open until you press the [esc] key instead of it auto-closing when it loses focus.

## Usage

The browser extension's pop-up menu contains three tabs:

* Wallet: displays credentials that can be displayed to a verifier
* About: displays information about the project
* Config: contains settings to reset the extension, configure the client helper service, and import a credential

Visiting an issuer website will trigger importation into the wallet.
