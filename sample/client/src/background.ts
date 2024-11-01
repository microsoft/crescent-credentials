/* eslint-disable indent */
/*
 *  Copyright (c) Microsoft Corporation.
 *  Licensed under the MIT license.
 */

/* eslint-disable @typescript-eslint/no-magic-numbers */

import { status, prepare, show } from './clientHelper.js'
import {
  MSG_POPUP_BACKGROUND_DISCLOSE, MSG_CONTENT_BACKGROUND_DISCLOSE_REQUEST, MSG_CONTENT_BACKGROUND_IMPORT_CARD,
  MSG_BACKGROUND_POPUP_DISCLOSE_REQUEST, MSG_BACKGROUND_POPUP_ERROR, MSG_BACKGROUND_POPUP_PREPARED,
  MSG_BACKGROUND_POPUP_PREPARE_STATUS, MSG_POPUP_BACKGROUND_PREPARE,
  MSG_POPUP_BACKGROUND_DELETE,
  MSG_BACKGROUND_CONTENT_SEND_PROOF,
  MSG_POPUP_BACKGROUND_IMPORT } from './constants.js'
import { listen } from './listen.js'
import { fetchText } from './utils.js'
import { Card, Wallet } from './cards.js'

console.debug('background.js: load')

chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') {
    console.debug('background.js: install')
  }
  else if (details.reason === 'update') {
    console.debug('background.js: update')
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

  await Wallet.init()
}

async function _setBadge (text: string): Promise<void> {
  await chrome.action.setBadgeText({ text })

  setTimeout(() => {
    void chrome.action.setBadgeText({ text: '' }) // Clear the badge
  }, 5000)
}

function _notify (title: string, message: string): void {
  chrome.notifications.create({
    type: 'basic',
    iconUrl: 'icons/icon128.png',
    title,
    message,
    requireInteraction: true
  })
}

async function disclosableCards (uid: string): Promise<Array<{ id: number, property: string }>> {
  const preparedCredentials = Wallet.cards.filter(card => card.status === 'PREPARED')
  const cardsWithUidValue = preparedCredentials.filter((card) => {
    return getDisclosureProperty(card, uid) !== null
  })
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  return cardsWithUidValue.map(card => ({ id: card.id, property: getDisclosureProperty(card, uid)! }))
}

function getDisclosureProperty (card: Card, uid: string): string | null {
  switch (uid) {
    case 'crescent://email_domain':
      // eslint-disable-next-line no-case-declarations
      const emailValue = (card.token.value as JWT_TOKEN).payload.email as string | undefined ?? ''
      return emailValue === '' ? null : emailValue.replace(/^.*@/, '')
    default:
      return null
  }
}

// MSG_CONTENT_BACKGROUND_IMPORT_CARD
listen<{ domain: string, encoded: string }>(MSG_CONTENT_BACKGROUND_IMPORT_CARD,
  async (data) => {
    // await importCard(data.url, data.jwt)
    const result = await Card.import(data.domain, data.encoded)
    if (!result.ok) {
      console.error('Failed to import:', result.error)
      return
    }
    await Wallet.add(result.value)
    return true
  }
)

// MSG_CONTENT_BACKGROUND_REQUEST_DISCLOSURE
listen<{ url: string, uid: string }>(MSG_CONTENT_BACKGROUND_DISCLOSE_REQUEST,
  async (data) => {
    const { url, uid } = data

    // await loadCards()

    if (typeof data.url !== 'string') {
      throw new Error('url is not a string')
    }

    if (typeof data.uid !== 'string') {
      throw new Error('uid is not a string')
    }

    await chrome.action.openPopup().catch((error) => {
      console.error('Failed to open popup window', error)
    })

    const issuerTokensIds = await disclosableCards(uid)

    void chrome.runtime.sendMessage({ action: MSG_BACKGROUND_POPUP_DISCLOSE_REQUEST, data: { issuerTokensIds, url, uid } }).catch((error) => {
      console.error('Failed to import JWT', error)
    })
  }
)

// MSG_POPUP_BACKGROUND_PREPARE
listen<{ id: number }>(MSG_POPUP_BACKGROUND_PREPARE,
  async (data) => {
    const id = data.id
    const card = Wallet.find(id)
    if (card === undefined) {
      throw new Error('Card not found')
    }
    let result = await prepare(card.issuer.url, card.data, 'https://schemas.crescent.dev/jwt/012345')
    let credUid = ''
    let p = 0
    if (result.ok) {
      credUid = result.value
      void chrome.runtime.sendMessage({ action: MSG_BACKGROUND_POPUP_PREPARE_STATUS, data: { id: card.id, progress: p } })
      card.status = 'PREPARING'
      card.credUid = credUid
      await card.save()
      // await updateCards()
    }
    else {
      console.error('Failed to prepare:', result.error)
      card.status = 'ERROR'
      await card.save()
      void chrome.runtime.sendMessage({ action: MSG_BACKGROUND_POPUP_ERROR, data: {} })
      return
    }

    result = await status (credUid,
      () => {
        p = Math.ceil((100 - p) * 0.05) + p
        card.progress = p
        void card.save().then(() => {
          void chrome.runtime.sendMessage({ action: MSG_BACKGROUND_POPUP_PREPARE_STATUS, data: { id: card.id, progress: p } }).catch((_error) => {
            console.warn('NO LISTENER', MSG_BACKGROUND_POPUP_PREPARE_STATUS)
          })
        })
      }
    )

    if (result.ok) {
      card.progress = 100
      card.status = 'PREPARED'
      void card.save().then(() => {
        void chrome.runtime.sendMessage({ action: MSG_BACKGROUND_POPUP_PREPARED, data: { id: card.id } })
      })
    }
    else {
      console.error('Failed to prepare:', result.error)
      card.status = 'ERROR'
      void card.save().then(() => {
        void chrome.runtime.sendMessage({ action: MSG_BACKGROUND_POPUP_ERROR, data: { id: card.id } })
      })
    }
  }
)

// MSG_POPUP_BACKGROUND_DISCLOSE
listen<{ id: number }>(MSG_POPUP_BACKGROUND_DISCLOSE,
  async (data) => {
    const card = Wallet.find(data.id)
    if (card === undefined) {
      throw new Error('Card not found')
    }
    const _showProof = await show(card)

    if (!_showProof.ok) {
      console.error('Failed to show proof:', _showProof.error)
      return
    }

    console.log('Show proof:', _showProof)

    await fetchText('http://127.0.0.1:8004/verify', { issuer_URL: card.issuer.url, schema_UID: 'https://schemas.crescent.dev/jwt/012345', proof: _showProof.value }, 'POST')

    const tabs = await chrome.tabs.query({ active: true, lastFocusedWindow: true })

    console.debug(tabs)

    const tabid = tabs[0].id

    if (tabid === undefined) {
      throw new Error('Tab not found')
    }

    const params = {
      url: 'http://fabrikam.com:8004/verify',
      issuer_URL: card.issuer.url,
      schema_UID: 'https://schemas.crescent.dev/jwt/012345',
      proof: _showProof.value
    }

    void chrome.tabs.sendMessage(tabid, { action: MSG_BACKGROUND_CONTENT_SEND_PROOF, data: params })
  }
)

// MSG_POPUP_BACKGROUND_DELETE
listen<{ id: number }>(MSG_POPUP_BACKGROUND_DELETE,
  async (data): Promise<void> => {
    await Wallet.remove(data.id)
    await Promise.resolve('deleted')
  }
)

// MSG_POPUP_BACKGROUND_IMPORT
listen<{ domain: string, encoded: string }>(MSG_POPUP_BACKGROUND_IMPORT,
  async (data) => {
    const result = await Card.import(data.domain, data.encoded)
    if (!result.ok) {
      console.error('Failed to import:', result.error)
      return
    }
    await Wallet.add(result.value)
    return true
  }
)

void init()
