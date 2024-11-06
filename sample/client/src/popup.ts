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
import config from './config.js'

chrome.runtime.onMessage.addListener((message: MESSAGE_PAYLOAD, sender) => {
  const dateNow = new Date(Date.now())
  console.debug('TOP-LEVEL LISTENER', dateNow.toLocaleString(), message, sender)
})

const puid = Math.random().toString(36).substring(7)

console.debug('popup.js: load', puid)

const PREPARED_MESSAGE_DURATION = 2000

const disclosureRequests: Array<{ ids: Array<{ id: number, property: string }>, url: string, uid: string }> = []
let _ready = false

function handleDisclosureRequest (): void {
  const request = disclosureRequests.pop()
  if (request === undefined) {
    return
  }

  const { ids, url, uid } = request

  ids.forEach((id) => {
    const entry = lookupCardElement(id.id)
    if (entry === undefined) {
      throw new Error('Entry not found')
    }
    entry.status = 'DISCLOSABLE'
    entry.disclose = (card: Card) => {
      void chrome.runtime.sendMessage({ action: MSG_POPUP_BACKGROUND_DISCLOSE, data: { id: card.id, url, uid } })
    }
    entry.discloseRequest(url, id.property, uid)
  })
}

async function init (): Promise<void> {
  console.debug('init start')

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
    console.debug('MSG_BACKGROUND_POPUP_DISCLOSE_REQUEST', data)
    const { url, uid } = data

    disclosureRequests.push({ ids: data.issuerTokensIds, url, uid })
    if (_ready) {
      handleDisclosureRequest()
    }
  })

  const _onReady: (() => void) | null = null

  await new Promise((resolve) => {
    // eslint-disable-next-line @typescript-eslint/no-misused-promises
    document.addEventListener('DOMContentLoaded', async function (): Promise<void> {
      // Init wallet data from store
      await Wallet.init(puid)

      const tabs = document.querySelectorAll<HTMLButtonElement>('.tab')
      tabs.forEach((tab) => {
        tab.addEventListener('click', () => {
          activateTab(tab)
        })
      })

      getElementById<HTMLInputElement>('button-import-card').addEventListener('click', () => {
        getElementById<HTMLInputElement>('file-import-file').click()
      })

      getElementById<HTMLInputElement>('file-import-file').addEventListener('change', (event) => {
        const fileControl = event.target as HTMLInputElement
        const file: File | undefined = fileControl.files?.[0]
        if (file == null) {
          return
        }
        const reader = new FileReader()
        reader.onload = importFileSelected
        reader.readAsText(file)
        // clear the value so that the change event is fired even if the same file is selected again
        fileControl.value = ''
      })

      const schemaDropDown = getElementById<HTMLSelectElement>('dropdown-import-schema')

      config.schemas.forEach((schema) => {
        const option = document.createElement('option')
        option.value = schema
        option.text = schema
        schemaDropDown.add(option)
      })

      const clientHelperUrlInput = getElementById<HTMLInputElement>('client-helper-url')

      clientHelperUrlInput.value = config.client_helper_url

      clientHelperUrlInput.addEventListener('change', function () {
        const url = clientHelperUrlInput.value

        void ping(url).then((connected: boolean) => {
          clientHelperUrlInput.style.background = connected ? 'lime' : 'red'
        })
      })

      // Init wallet UI from wallet data
      await initWallet ()

      _ready = true
      handleDisclosureRequest()

      resolve(true)
    })
  })

  console.debug('init done')
}

async function importFileSelected (event: ProgressEvent<FileReader>): Promise<void> {
  const encoded = event.target?.result as string
  const schema = getElementById<HTMLSelectElement>('dropdown-import-schema').value
  const result = await chrome.runtime.sendMessage<MESSAGE_PAYLOAD, RESULT<Card, Error>>({ action: MSG_POPUP_BACKGROUND_IMPORT, data: { encoded, domain: importSettings.domain, schema } })

  if (!result.ok) {
    await showError(result.error.message)
    return
  }

  await Wallet.reload()

  await initWallet ()

  showTab('wallet')
}

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
  getElementById<HTMLDivElement>(tabContentId).classList.add('active-content')
}

async function sendBackgroundMessage<T> (action: string, data: Record<string, unknown>): Promise<T> {
  return await chrome.runtime.sendMessage({ action, data })
}

function showTab (name: string): void {
  const tab = document.querySelector<HTMLButtonElement>(`button[data-tab="${name}"`)
  if (tab === null) {
    throw new Error(`Tab ${name} not found`)
  }
  activateTab(tab)
}

async function initWallet (): Promise<void> {
  console.debug('initWallet start')
  const walletDiv = getElementById<HTMLDivElement>('wallet-info')
  walletDiv.replaceChildren()
  Wallet.cards.forEach((card) => {
    console.debug(card)
    addWalletEntry(card)
  })
  console.debug('initWallet done')
}

function addWalletEntry (_card: Card): void {
  const walletDiv = getElementById<HTMLDivElement>('wallet-info')
  const cardComponent = document.createElement('card-element') as CardElement
  cardComponent.card = _card
  walletDiv.appendChild(cardComponent)

  cardComponent.status = _card.status

  cardComponent.accept = (card: Card) => {
    void sendBackgroundMessage<RESULT<string, Error>>(MSG_POPUP_BACKGROUND_PREPARE, { id: card.id })
      .then(async (result) => {
        if (!result.ok) {
          await showError(result.error.message)
          cardComponent.status = 'PENDING'
        }
      })
  }

  cardComponent.reject = (_card: Card) => {
    walletDiv.removeChild(cardComponent)
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
  const walletDiv = getElementById<HTMLDivElement>('wallet-info')
  return Array.from(walletDiv.children).find((child) => {
    const cardElement = child as CardElement
    if (cardElement.card == null) return false
    return cardElement.card.id === id
  }) as CardElement | undefined
}

const importSettings: { domain: string | null, schema: string | null } = {
  domain: null,
  schema: null
}

getElementById<HTMLInputElement>('text-import-domain').addEventListener('input', function (event) {
  const value = (event.target as HTMLInputElement).value
  const buttonImportFile = getElementById<HTMLInputElement>('button-import-card')
  const domainPattern = /^(?:(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}|\d{1,3}(?:\.\d{1,3}){3})(?::\d{1,5})?$/

  const validDomain = domainPattern.test(value)
  if (validDomain) {
    importSettings.domain = value
  }
  buttonImportFile.disabled = !validDomain
  validDomain ? buttonImportFile.classList.remove('config-button-disabled') : buttonImportFile.classList.add('config-button-disabled')
})

void init().then(() => {

})

async function showError (message: string): Promise<void> {
  await new Promise<void>((resolve) => {
    const overlay = getElementById<HTMLDivElement>('overlay')
    const error = getElementById<HTMLDivElement>('error-dialog')
    const errorMessage = getElementById<HTMLParagraphElement>('error-overlay-message')
    const errorButton = getElementById<HTMLInputElement>('error-overlay-button')
    overlay.classList.add('overlay-error')
    overlay.style.display = 'flex'
    error.style.display = 'inline-block'
    errorMessage.innerText = message
    errorButton.onclick = () => {
      closeOverlay()
      resolve()
    }
  })
}

function closeOverlay (): void {
  const overlay = getElementById<HTMLDivElement>('overlay')
  const error = getElementById<HTMLDivElement>('error-dialog')
  const pick = getElementById<HTMLDivElement>('pick-dialog')
  overlay.classList.remove('overlay-error', 'pick')
  overlay.style.display = 'none'
  error.style.display = 'none'
  pick.style.display = 'none'
}
