/*
 *  Copyright (c) Microsoft Corporation.
 *  Licensed under the MIT license.
 */

import { MSG_NOTIFY_CRESCENT_DISCLOSURE_URI, MSG_NOTIFY_CRESCENT_META } from './constants.js'

console.debug('content.js: load')

const metaTagJwt = document.querySelector('meta[name="CRESCENT_JWT"]')
if (metaTagJwt != null) {
  const metaValue = metaTagJwt.getAttribute('content')
  console.log('Detected meta value:', metaValue)
  insertBanner(`Crescent CRESCENT_JWT detected: ${metaValue}`)
  const domain = new URL(window.location.href).hostname
  /*
    Store the JWT from this site in the background script
  */
  void chrome.runtime.sendMessage({ action: MSG_NOTIFY_CRESCENT_META, data: { jwt: metaValue, url: domain } })
}

const metaTagDisclosure = document.querySelector('meta[crescent="CRESCENT_DISCLOSURE_URI"]')
if (metaTagDisclosure != null) {
  const metaValue = metaTagDisclosure.getAttribute('crescent')
  console.log('Detected meta value:', metaValue)
  insertBanner(`Crescent CRESCENT_DISCLOSURE_URI detected: ${metaValue}`)
  const domain = new URL(window.location.href).hostname
  /*
    Store the JWT from this site in the background script
  */
  void chrome.runtime.sendMessage({ action: MSG_NOTIFY_CRESCENT_DISCLOSURE_URI, data: {} })
}

// Function to create and insert a banner at the top of the page
function insertBanner (message: string): void {
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
