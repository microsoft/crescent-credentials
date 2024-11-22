/*
 *  Copyright (c) Microsoft Corporation.
 *  Licensed under the MIT license.
 */

/* eslint-disable @typescript-eslint/no-magic-numbers */

import { MSG_BACKGROUND_CONTENT_SEND_PROOF, MSG_CONTENT_BACKGROUND_IMPORT_CARD, MSG_POPUP_CONTENT_SCAN_DISCLOSURE } from './constants.js'
import { sendMessage } from './listen.js'
import { assert } from './utils.js'

console.debug('content.js: load')

async function scanForCredential (): Promise<void> {
  const metaTagJwt = document.querySelector('meta[name="CRESCENT_JWT"]')
  if (metaTagJwt != null) {
    const metaValue = metaTagJwt.getAttribute('content')
    console.log('Detected meta value:', metaValue)
    const domain = new URL(window.location.href).origin
    await sendMessage('background', MSG_CONTENT_BACKGROUND_IMPORT_CARD, domain, 'jwt_corporate_1', metaValue)
  }
}

function queryDisclosureRequest (): { url: string, uid: string } | null {
  const verifyUrl = document.querySelector('meta[crescent_verify_url]')?.getAttribute('crescent_verify_url') ?? ''
  const disclosureUid = document.querySelector('meta[crescent_disclosure_uid]')?.getAttribute('crescent_disclosure_uid') ?? ''
  if (verifyUrl.length > 0 && disclosureUid.length > 0) {
    return { url: verifyUrl, uid: disclosureUid }
  }
  return null
}

// Function to create and insert a banner at the top of the page
function _insertBanner (message: string): void {
  const banner = document.createElement('div')

  // Style the banner
  banner.style.position = 'fixed'
  banner.style.top = '0' // Place at the top of the page
  banner.style.left = '0'
  banner.style.width = '100%'
  banner.style.backgroundColor = '#4E95D9'
  banner.style.color = '#000'
  banner.style.textAlign = 'center'
  banner.style.padding = '15px'
  banner.style.fontSize = '18px'
  banner.style.zIndex = '10000' // Ensure it stays on top
  banner.style.boxShadow = '0px 2px 10px rgba(0, 0, 0, 0.1)' // Shadow below the banner

  // Set the banner content
  banner.textContent = message

  // Append the banner to the body
  document.body.appendChild(banner)

  // Optional: Add a close button
  const closeButton = document.createElement('span')
  closeButton.textContent = '✕'
  closeButton.style.float = 'right'
  closeButton.style.marginRight = '15px'
  closeButton.style.cursor = 'pointer'
  closeButton.style.fontWeight = 'bold'
  closeButton.onclick = () => {
    banner.remove() // Remove the banner when the close button is clicked
  }
  banner.appendChild(closeButton)
}

// listen for meesgae from background
chrome.runtime.onMessage.addListener((request, _sender, sendResponse) => {
  if (request.action === MSG_BACKGROUND_CONTENT_SEND_PROOF) {
    console.log('Received proof:', request.data)
    const params = request.data[0]
    assert(params)

    fetch(params.url as string, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(params),
      redirect: 'follow'
    })
      .then(async (response) => {
        if (response.status === 200) {
          window.location.href = response.url
        }
        else {
          console.log('Received non-redirect response:', response)
          return await response.json()
        }
      })
      .catch((error) => {
        console.error('Error sending proof:', error)
      })
    return null
  }

  if (request.action === MSG_POPUP_CONTENT_SCAN_DISCLOSURE) {
    sendResponse(queryDisclosureRequest())
  }
})

/*
  If the page is navigated to from forward or back button, scan for credential and disclosure requests.
  The page may used a cached version of the page, so the content script may not re-run.
*/
window.addEventListener('pageshow', (event) => {
  if (event.persisted) {
    console.debug('scanForDisclosureRequest pageshow')
  }
})

void scanForCredential ()
