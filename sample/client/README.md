# Crescent sample client browser extension

This project contains a Edge/Chrome/Firefox browser extension implementing a Crescent prover. The browser extension can interact with the [sample issuer](../issuer/README.md) to retrieve JSON Web Tokens (JWT) and present a Crescent zero-knowledge proof to the [sample verifier](../verifier/README.md), with the help of a [client helper](../client_helper/README.md) to offload expensive storage and computation.

## Setup

Make sure [node.js](https://nodejs.org/) and [npm](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm) are installed on your system; the latest Long-Term Support (LTS) version is recommended for both.

Run the install script:

`npm install`

## Build

Build the extension (3 modes):

* production build (minified w/o sourcemapping)  
`npm run build`

* debug build (no minification and sourcemapping enabled)  
`npm run build:debug`

* watch build (watches files and does debug build on save)  
`npm run build:watch`

## Installation

<div style="padding-left: 2em">
Follow the side-loading instruction for your browser to load the extension:

[Edge](https://learn.microsoft.com/en-us/microsoft-edge/extensions-chromium/getting-started/extension-sideloading)  
[Chrome](https://developer.chrome.com/docs/extensions/mv3/getstarted/development-basics/#load-unpacked)  
[Firefox](https://extensionworkshop.com/documentation/develop/temporary-installation-in-firefox/) 

The Edge/Chrome `manifest.json` file is located at `samples/browser-extension/dist/chrome`  
The Firefox `manifest.json` file is located at `samples/browser-extension/dist/firefox`  

Firefox requires additional extension permissions to download manifests from external sites
1) In the Firefox address bar go to `about:addons` to see the installed extensions
2) Find **Crescent Browser Extension** and click the `...` button to the right
3) Select **Manage** from the pop-up menu
4) Click the **Permission** tab
5) Enable **Access your data for all websites**
</div>

## Usage

The browser extension's pop-up menu contains three tabs:
* Wallet: displays credentials that can be displayed to a verifier
* About: displays information about the project
* Config: contains settings to reset the extension, configure the client helper service, and import a credential

Visiting an issuer website will trigger importation into the wallet.
