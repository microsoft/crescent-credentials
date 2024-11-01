/*
 *  Copyright (c) Microsoft Corporation.
 *  Licensed under the MIT license.
 */

/* eslint-disable @typescript-eslint/no-magic-numbers */

import { type Card, Wallet } from './cards.js'
import { ping } from './clientHelper.js'
import type { CardElement } from './components/card.js'
import {
  MSG_POPUP_BACKGROUND_DISCLOSE, MSG_BACKGROUND_POPUP_DISCLOSE_REQUEST, MSG_BACKGROUND_POPUP_PREPARED,
  MSG_BACKGROUND_POPUP_PREPARE_STATUS, MSG_POPUP_BACKGROUND_PREPARE, MSG_POPUP_BACKGROUND_IMPORT,
  MSG_POPUP_BACKGROUND_DELETE
} from './constants.js'
import { listen } from './listen.js'
import { getElementById } from './utils.js'

console.debug('popup.js: load')

const PREPARED_MESSAGE_DURATION = 2000

document.addEventListener('DOMContentLoaded', function (): void {
  void Wallet.init().then(() => {
  // Add event listeners to switch tabs
    const tabs = document.querySelectorAll<HTMLButtonElement>('.tab')
    tabs.forEach((tab) => {
      tab.addEventListener('click', () => {
        activateTab(tab)
      })
    })

    getElementById('button-import-card').addEventListener('click', () => {
      getElementById('file-import-file').click()
    })

    getElementById('file-import-file').addEventListener('change', (event) => {
      const file: File | undefined = (event.target as HTMLInputElement | undefined)?.files?.[0]
      if (file == null) {
        return
      }

      const reader = new FileReader()
      reader.onload = async function (event) {
        const encoded = event.target?.result as string
        void chrome.runtime.sendMessage({ action: MSG_POPUP_BACKGROUND_IMPORT, data: { encoded, domain: importSettings.domain } })
          .then(async (_result: RESULT<string, Error>) => {
            await Wallet.reload()
          })
          .then(() => {
            void initWallet ()
          })
      }

      reader.readAsText(file)
    })

    const clientHelperUrlInput = getElementById('client-helper-url') as HTMLInputElement

    clientHelperUrlInput.value = process.env.CLIENT_HELPER_URL ?? '127.0.0.1:8003'

    clientHelperUrlInput.addEventListener('change', function () {
      const url = clientHelperUrlInput.value

      void ping(url).then((connected: boolean) => {
        clientHelperUrlInput.style.background = connected ? 'lime' : 'red'
      })
    })
  })
})

function activateTab (tab: HTMLElement): void {
  const tabContents = document.querySelectorAll<HTMLDivElement>('.tab-content')
  // Remove active classes
  const tabs = document.querySelectorAll('.tab')
  tabs.forEach((t) => {
    t.classList.remove('active')
  })
  tabContents.forEach((c) => {
    c.classList.remove('active-content')
  })

  // Add the active class to the selected tab
  tab.classList.add('active')

  // Active the content section for the selected tab
  const tabContentId = tab.getAttribute('data-tab') ?? ''
  if (tabContentId === '') {
    throw new Error('Tab does not have a data-tab attribute')
  }
  getElementById(tabContentId).classList.add('active-content')
}

async function sendBackgroundMessage<T> (action: string, data: Record<string, unknown>): Promise<T> {
  return await chrome.runtime.sendMessage({ action, data })
}

function _showTab (name: string): void {
  const tab = document.querySelector<HTMLButtonElement>(`button[data-tab="${name}"`)
  if (tab === null) {
    throw new Error(`Tab ${name} not found`)
  }
  activateTab(tab)
}

async function initWallet (): Promise<void> {
  const walletDiv = getElementById('wallet-info')
  walletDiv.replaceChildren()
  Wallet.cards.forEach((card) => {
    console.debug(card)
    addWalletEntry(card)
  })
}

function addWalletEntry (_card: Card): void {
  const walletDiv = getElementById('wallet-info')
  const cardComponent = document.createElement('card-element') as CardElement
  cardComponent.card = _card
  walletDiv.appendChild(cardComponent)

  cardComponent.status = _card.status

  cardComponent.accept = (card: Card) => {
    void sendBackgroundMessage(MSG_POPUP_BACKGROUND_PREPARE, { id: card.id })
  }

  cardComponent.reject = (_card: Card) => {
    walletDiv.removeChild(cardComponent)
  }

  cardComponent.disclose = (card: Card) => {
    void chrome.runtime.sendMessage({ action: MSG_POPUP_BACKGROUND_DISCLOSE, data: { id: card.id } })
  }

  cardComponent.delete = function (card: Card) {
    walletDiv.removeChild(cardComponent)
    void chrome.runtime.sendMessage({ action: MSG_POPUP_BACKGROUND_DELETE, data: { id: card.id } }).then(() => {
      // void loadCards()
      void Wallet.reload()
    })
  }
}

function _lookupCard (id: number): Card | undefined {
  return Wallet.find(id)
}

function lookupCardElement (id: number): CardElement | undefined {
  const walletDiv = getElementById('wallet-info')
  return Array.from(walletDiv.children).find((child) => {
    const cardElement = child as CardElement
    if (cardElement.card == null) return false
    return cardElement.card.id === id
  }) as CardElement | undefined
}

const importSettings: { domain: string | null, schema: string, file: string | null } = {
  domain: null,
  schema: 'https://schemas.crescent.dev/jwt/012345',
  file: null
}

getElementById('text-import-domain').addEventListener('input', function (event) {
  const value = (event.target as HTMLInputElement).value
  const buttonImportFile = getElementById('button-import-card') as HTMLInputElement
  const domainPattern = /^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/
  const validDomain = domainPattern.test(value)
  if (validDomain)importSettings.domain = value
  buttonImportFile.disabled = !validDomain
  validDomain ? buttonImportFile.classList.remove('config-button-disabled') : buttonImportFile.classList.add('config-button-disabled')
})

// MSG_BACKGROUND_POPUP_PREPARE_STATUS
listen<{ id: number, progress: number }>(MSG_BACKGROUND_POPUP_PREPARE_STATUS, (data) => {
  const { id, progress } = data
  const entry = lookupCardElement(id)
  if (entry?.card == null) {
    throw new Error('Card is null')
  }
  entry.progress.value = progress
})

// MSG_BACKGROUND_POPUP_PREPARED
listen<{ id: number }>(MSG_BACKGROUND_POPUP_PREPARED, (data) => {
  const { id } = data
  const entry = lookupCardElement(id)
  if (entry?.card == null) {
    throw new Error('Card is null')
  }

  entry.progress.value = 100
  entry.progress.label = 'Prepared'
  setTimeout(() => {
    entry.progress.hide()
  }, PREPARED_MESSAGE_DURATION)
})

// MSG_BACKGROUND_POPUP_DISCLOSE_REQUEST
listen<{ issuerTokensIds: Array<{ id: number, property: string }>, url: string, uid: string }>(MSG_BACKGROUND_POPUP_DISCLOSE_REQUEST, (data) => {
  const { url: pageUrl, uid } = data
  data.issuerTokensIds.forEach((id) => {
    const entry = lookupCardElement(id.id)
    if (entry === undefined) {
      throw new Error('Entry not found')
    }
    entry.status = 'DISCLOSABLE'
    entry.discloseRequest(pageUrl, id.property, uid)
  })
})
