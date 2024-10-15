/*
 *  Copyright (c) Microsoft Corporation.
 *  Licensed under the MIT license.
 */

/* eslint-disable @typescript-eslint/no-magic-numbers */

import { AWAIT_ASYNC_RESPONSE, MSG_NOTIFY_CRESCENT_DISCLOSURE_URI, MSG_NOTIFY_CRESCENT_META, MSG_POPUP_DISPLAY_JWTS } from './constants.js'
import { addData, getData } from './indexeddb.js'
import { decodeJwt } from './jwt.js'

console.debug('background.js: load')

chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') {
    console.debug('background.js: install')
  }
  else if (details.reason === 'update') {
    console.debug('background.js: update')
  }
})

chrome.runtime.onMessage.addListener((message: MESSAGE_PAYLOAD, sender, _sendResponse) => {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const _tabId = sender.tab?.id
  const action = message.action
  const data = message.data as Record<string, unknown>

  if (action === MSG_NOTIFY_CRESCENT_META) {
    const payload = data as { url: string, jwt: string }
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icons/icon128.png',
      title: 'Crescent Meta Detected',
      message: payload.jwt,
      requireInteraction: true
    })

    const decodedJwt: JWT = decodeJwt(payload.jwt)

    console.log('Decoded JWT:', decodedJwt)

    void getData<JWT_RECORDS>('crescent', 'jwts')
      .then(async (jwts: JWT_RECORDS | undefined) => {
        if (jwts === undefined) {
          jwts = []
        }

        // Update the JWT for the domain if it already exists
        const index = jwts.findIndex(jwt => jwt.url === payload.url)
        if (index !== -1) {
          jwts[index].jwt = decodedJwt
        }
        else {
          jwts.push({ url: payload.url, jwt: decodedJwt })
        }

        return await addData<JWT_RECORDS>('crescent', 'jwts', jwts)
      })
      .then(() => {
        void chrome.action.setBadgeText({ text: 'New' })
        setTimeout(() => {
          void chrome.action.setBadgeText({ text: '' }) // Clear the badge
        }, 5000)
        void chrome.action.openPopup()
      })
    return AWAIT_ASYNC_RESPONSE
  }

  if (action === MSG_NOTIFY_CRESCENT_DISCLOSURE_URI) {
    const _payload = data as object
    void getData<JWT_RECORDS>('crescent', 'jwts')
      .then(async (jwts: JWT_RECORDS | undefined) => {
        if (jwts === undefined) {
          // do nothing
          return
        }
        // send message to popup to display the jwts
        void chrome.action.openPopup()
        void chrome.runtime.sendMessage({ action: MSG_POPUP_DISPLAY_JWTS, data: {} })
      })
    return AWAIT_ASYNC_RESPONSE
  }
})

async function init (): Promise<void> {
  // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
  if (chrome.offscreen !== undefined) {
    if (await chrome.offscreen.hasDocument()) {
      return
    }

    await chrome.offscreen
      .createDocument({
        url: 'offscreen.html',
        reasons: [chrome.offscreen.Reason.DOM_PARSER],
        justification: 'Private DOM access to parse HTML'
      })
      .catch((error) => {
        console.error('Failed to create offscreen document', error)
      })
  }
}

void init()
