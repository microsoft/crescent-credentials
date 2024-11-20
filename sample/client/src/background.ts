/*
 *  Copyright (c) Microsoft Corporation.
 *  Licensed under the MIT license.
 */

/* eslint-disable @typescript-eslint/no-magic-numbers */

import {
  MSG_CONTENT_BACKGROUND_IMPORT_CARD,
  MSG_POPUP_BACKGROUND_UPDATE,
  MSG_POPUP_CONTENT_SCAN_DISCLOSURE,
  MSG_BACKGROUND_POPUP_IS_OPEN,
  MSG_BACKGROUND_POPUP_ACTIVE_TAB_UPDATE
} from './constants.js'
import { sendMessage, setListener } from './listen.js'
import { Credential } from './cred.js'
import './clientHelper.js'
import './verifier.js'
import { messageToActiveTab, openPopup } from './utils.js'
import config from './config.js'

console.debug('background.js: load')

chrome.runtime.onMessage.addListener((message: MESSAGE_PAYLOAD, sender) => {
  const dateNow = new Date(Date.now())
  console.debug('TOP-LEVEL LISTENER', dateNow.toLocaleString(), message, sender)
})

chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') {
    console.debug('background.js: install')
  }
  else if (details.reason === 'update') {
    console.debug('background.js: update')
  }
})

const listener = setListener('background')

const settings = {
  autoOpen: false
}

async function init (): Promise<void> {
  await Credential.load()
  const autoOpenObj = await chrome.storage.local.get(['autoOpen'])
  settings.autoOpen = autoOpenObj.autoOpen ?? config.autoOpen
  console.debug('background.js: init')
}

listener.handle(MSG_CONTENT_BACKGROUND_IMPORT_CARD, async (domain: string, schema: string, encoded: string) => {
  const cred = new Credential(domain, schema, encoded)
  await cred.save()
  await Credential.load()
  settings.autoOpen && await openPopup()
  return true
})

listener.handle(MSG_POPUP_BACKGROUND_UPDATE, async () => {
  await Credential.load()
  const autoOpenObj = await chrome.storage.local.get(['autoOpen'])
  settings.autoOpen = autoOpenObj.autoOpen ?? config.autoOpen
  console.log(Credential.creds)
})

void init().then(() => {
  listener.go()
})

async function isPopupOpen (): Promise<boolean> {
  const result = await sendMessage<boolean>('popup', MSG_BACKGROUND_POPUP_IS_OPEN).catch(() => {
    return false
  })
  return result
}

/*
  When the active tab changes, send a message to the active tab to scan for disclosure requests.
*/
chrome.tabs.onActivated.addListener((_activeInfo) => {
  void messageToActiveTab(MSG_POPUP_CONTENT_SCAN_DISCLOSURE)
})

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  void (async () => {
    if (changeInfo.status === 'complete' && tab.url != null && tab.active) {
      const disclosureRequest = await messageToActiveTab<{ url: string, uid: string } | null>(MSG_POPUP_CONTENT_SCAN_DISCLOSURE)

      if (disclosureRequest == null) {
        // No disclosure request found
        return
      }

      const popupOpen = await isPopupOpen()

      if (!settings.autoOpen && !popupOpen) {
        // Do nothing. The popup will query for the disclosure request itself when it opens.
        return
      }

      if (settings.autoOpen && !popupOpen) {
        // Open the popup and it will query for the disclosure request itself.
        await openPopup()
        return
      }

      // The popup is open. Send the disclosure request to the popup.
      void sendMessage('popup', MSG_BACKGROUND_POPUP_ACTIVE_TAB_UPDATE)
    }
  })()
})
