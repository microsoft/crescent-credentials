/*
 *  Copyright (c) Microsoft Corporation.
 *  Licensed under the MIT license.
 */

/* eslint-disable @typescript-eslint/no-magic-numbers */

import { status, prepare, show } from './clientHelper.js'
import {
  MSG_POPUP_BACKGROUND_DISCLOSE, MSG_CONTENT_BACKGROUND_DISCLOSE_REQUEST, MSG_CONTENT_BACKGROUND_IMPORT_CARD,
  MSG_BACKGROUND_POPUP_DISCLOSE_REQUEST, MSG_BACKGROUND_POPUP_ERROR, MSG_BACKGROUND_POPUP_PREPARED,
  MSG_BACKGROUND_POPUP_PREPARE_STATUS, MSG_POPUP_BACKGROUND_PREPARE, MSG_POPUP_BACKGROUND_DELETE,
  MSG_BACKGROUND_CONTENT_SEND_PROOF, MSG_POPUP_BACKGROUND_IMPORT
} from './constants.js'
import { sendMessage, setListener } from './listen.js'
import { fetchText } from './utils.js'
import { Card, Wallet } from './cards.js'

const bgid = Math.random().toString(36).substring(7)

console.debug('background.js: load', bgid)

chrome.runtime.onMessage.addListener((message: MESSAGE_PAYLOAD, sender) => {
  const dateNow = new Date(Date.now())
  console.debug('TOP-LEVEL LISTENER', dateNow.toLocaleString(), message, sender)
})

const listener = setListener('background')

chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') {
    console.debug('background.js: install')
  }
  else if (details.reason === 'update') {
    console.debug('background.js: update')
  }
})

async function init (): Promise<void> {
  console.debug('background.js: init', bgid)
  await Wallet.init(bgid)
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
      // eslint-disable-next-line no-case-declarations, @typescript-eslint/no-unnecessary-condition
      const emailValue = (card.token.value as JWT_TOKEN | undefined)?.payload?.email as string | undefined ?? ''
      return emailValue === '' ? null : emailValue.replace(/^.*@/, '')
    default:
      return null
  }
}

listener.handle(MSG_CONTENT_BACKGROUND_IMPORT_CARD, async (domain: string, schema: string, encoded: string) => {
  const result = await Card.import(domain, schema, encoded)
  if (!result.ok) {
    console.error('Failed to import:', result.error)
    return false
  }
  await Wallet.add(result.value)
  await chrome.action.openPopup().catch((error) => {
    console.warn('Failed to open popup window', error)
  })
  return true
})

listener.handle(MSG_POPUP_BACKGROUND_DELETE, async (id: number) => {
  await Wallet.remove(id)
  await Promise.resolve('deleted')
})

listener.handle(MSG_POPUP_BACKGROUND_PREPARE, async (id: number) => {
  const card = Wallet.find(id)
  if (card === undefined) {
    throw new Error('Card not found')
  }
  let result = await prepare(card.issuer.url, card.data, card.token.schema)

  if (!result.ok) {
    return { ok: false, error: { message: 'Prepare failed. Check Client-Helper service.', name: 'Error' } }
  }

  const resultOk = result as { ok: true, value: string }

  let credUid = ''
  let p = 0

  credUid = resultOk.value
  void sendMessage('popup', MSG_BACKGROUND_POPUP_PREPARE_STATUS, card.id, p)
  card.status = 'PREPARING'
  card.credUid = credUid
  await card.save()

  result = await status (credUid,
    () => {
      p = Math.ceil((100 - p) * 0.05) + p
      card.progress = p
      void card.save().then(() => {
        void sendMessage('popup', MSG_BACKGROUND_POPUP_PREPARE_STATUS, card.id, p).catch((_error) => {
          console.warn('NO LISTENER', MSG_BACKGROUND_POPUP_PREPARE_STATUS)
        })
      })
    }
  )

  if (result.ok) {
    card.progress = 100
    card.status = 'PREPARED'
    void card.save().then(() => {
      void sendMessage('popup', MSG_BACKGROUND_POPUP_PREPARED, card.id)
    })
  }
  else {
    console.error('Failed to prepare:', result.error)
    card.status = 'ERROR'
    void card.save().then(() => {
      void sendMessage('popup', MSG_BACKGROUND_POPUP_ERROR, card.id)
    })
  }
}
)

listener.handle(MSG_POPUP_BACKGROUND_IMPORT, async (domain: string, schema: string, encoded: string) => {
  const result = await Card.import(domain, schema, encoded)
  if (!result.ok) {
    console.error('Failed to import:', result.error)
    return { ...result, error: { message: result.error.message, name: result.error.name } }
  }
  await Wallet.add(result.value)
  return result
}
)

listener.handle(MSG_CONTENT_BACKGROUND_DISCLOSE_REQUEST, async (url: string, uid: string) => {
  // await loadCards()

  if (typeof url !== 'string') {
    throw new Error('url is not a string')
  }

  if (typeof uid !== 'string') {
    throw new Error('uid is not a string')
  }

  await chrome.action.openPopup().catch((error) => {
    console.warn('Failed to open popup window', error)
  })

  const issuerTokensIds = await disclosableCards(uid)

  void sendMessage('popup', MSG_BACKGROUND_POPUP_DISCLOSE_REQUEST, issuerTokensIds, url, uid).catch((error) => {
    console.error('Failed to import JWT', error)
  })
}
)

listener.handle(MSG_POPUP_BACKGROUND_DISCLOSE, async (id: number, uid: string, url: string) => {
  const card = Wallet.find(id)
  if (card === undefined) {
    throw new Error('Card not found')
  }
  const _showProof = await show(card)

  if (!_showProof.ok) {
    console.error('Failed to show proof:', _showProof.error)
    return
  }

  const tabs = await chrome.tabs.query({ active: true, lastFocusedWindow: true })
  if (tabs.length === 0) {
    throw new Error('No active tab found')
  }

  const tabid = tabs[0].id

  if (tabid === undefined) {
    throw new Error('Tab not found')
  }

  // TODO: remove hardcoded URL
  const params = {
    url,
    disclosure_uid: uid,
    issuer_URL: card.issuer.url,
    schema_UID: card.token.schema,
    proof: _showProof.value
  }

  void chrome.tabs.sendMessage(tabid, { action: MSG_BACKGROUND_CONTENT_SEND_PROOF, data: params })
}
)

void init().then(() => {
  listener.go()
})
