/*
 *  Copyright (c) Microsoft Corporation.
 *  Licensed under the MIT license.
 */

/* eslint-disable @typescript-eslint/no-magic-numbers */

import {
  MSG_BACKGROUND_POPUP_ACTIVE_TAB_UPDATE, MSG_BACKGROUND_POPUP_ERROR, MSG_BACKGROUND_POPUP_IS_OPEN, MSG_BACKGROUND_POPUP_PREPARED,
  MSG_BACKGROUND_POPUP_PREPARE_STATUS, MSG_POPUP_BACKGROUND_UPDATE, MSG_POPUP_CONTENT_SCAN_DISCLOSURE
} from './constants.js'
import { ping } from './clientHelper.js'
import { sendMessage, setListener } from './listen.js'
import { assert, getElementById, messageToActiveTab } from './utils.js'
import { Credential, CredentialWithCard } from './cred.js'
import config from './config.js'
import type { ToggleSwitch } from './components/toggle.js'

const PREPARED_MESSAGE_DURATION = 2000
const settings = {
  autoOpen: false
}

console.debug('popup.js: load')

const listener = setListener('popup')

let observer: MutationObserver | null = null

const importSettings: { domain: string | null, schema: string | null } = {
  domain: null,
  schema: null
}

chrome.runtime.onMessage.addListener((message: MESSAGE_PAYLOAD, sender, _sendResponse) => {
  const dateNow = new Date(Date.now())
  console.debug('TOP-LEVEL LISTENER', dateNow.toLocaleString(), message, sender)
})

async function init (): Promise<void> {
  console.debug('init start')

  await new Promise((resolve, _reject) => {
    // eslint-disable-next-line @typescript-eslint/no-misused-promises
    document.addEventListener('DOMContentLoaded', async function (): Promise<void> {
      /*
        Init the auto-open toggle switch
      */
      const autoOpenObj = await chrome.storage.local.get(['autoOpen'])
      settings.autoOpen = autoOpenObj.autoOpen ?? config.autoOpen
      const toggleAutoOpen = getElementById<ToggleSwitch>('toggleAutoOpenOnDisclosure')
      // Save the auto-open setting to storage whenever the toggle is changed
      toggleAutoOpen.addEventListener('change', (event) => {
        const checked = (event as CustomEvent).detail.checked as boolean
        void chrome.storage.local.set({ autoOpen: checked })
        void sendMessage('background', MSG_POPUP_BACKGROUND_UPDATE)
      })
      toggleAutoOpen.checked = settings.autoOpen
      toggleAutoOpen.requestUpdate() // TODD: This should not be required to update the toggle UI state

      /*
        Set click handlers on the tabs
      */
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

      /*
        Display/Hide browser specific items
      */
      if (navigator.userAgent.includes('Firefox')) {
        // Display the note about Firefox auto-close issue
        const firefoxNote = getElementById<HTMLDivElement>('firefox-note')
        firefoxNote.style.display = 'block'
        // Set the base font size to 12px for Firefox as it renders larger
        document.documentElement.style.fontSize = '12px'
      }
      else {
        // The auto-open only works on Chrome/Edge. Firefox cannot open the popup programmatically
        const autoOpenSection = getElementById<HTMLDivElement>('toggle-auto-open')
        autoOpenSection.style.display = 'block'
      }

      /*
        Click handler for the popup close button
      */
      const closePopupButton = getElementById<HTMLInputElement>('close-popup')
      closePopupButton.addEventListener('click', () => {
        window.close()
      })

      /*
        Add the schemas to the dropdown
      */
      const schemaDropDown = getElementById<HTMLSelectElement>('dropdown-import-schema')
      config.schemas.forEach((schema) => {
        const option = document.createElement('option')
        option.value = schema
        option.text = schema
        schemaDropDown.add(option)
      })

      /*
        Init client helper URL input
      */
      const clientHelperUrlInput = getElementById<HTMLInputElement>('client-helper-url')
      clientHelperUrlInput.value = config.clientHelperUrl
      clientHelperUrlInput.addEventListener('change', function () {
        const url = clientHelperUrlInput.value
        void ping(url).then((connected: boolean) => {
          clientHelperUrlInput.style.background = connected ? 'lime' : 'red'
        })
      })

      // Init wallet UI from wallet data
      await initWallet()

      resolve(true)
    })
  })

  console.debug('init done')
}

async function scanForDisclosureRequest (): Promise<void> {
  const disclosureRequest = await messageToActiveTab<{ url: string, uid: string, challenge: string, proofSpec: string } | null>(MSG_POPUP_CONTENT_SCAN_DISCLOSURE)
  console.debug('disclosureRequest', disclosureRequest)
  if (disclosureRequest != null) {
    CredentialWithCard.creds.forEach((cred) => {
      cred.discloserRequest(disclosureRequest.url, disclosureRequest.uid, disclosureRequest.challenge, disclosureRequest.proofSpec)
    })
  }
}

async function importFileSelected (event: ProgressEvent<FileReader>): Promise<void> {
  const encoded = event.target?.result as string
  const schema = getElementById<HTMLSelectElement>('dropdown-import-schema').value
  assert(importSettings.domain)

  try {
    const cred = new Credential(importSettings.domain, schema, encoded)
    await cred.save()
  }
  catch (error) {
    await showError((error as Error).message)
    return
  }

  await initWallet()

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

function showTab (name: string): void {
  const tab = document.querySelector<HTMLButtonElement>(`button[data-tab="${name}"`)
  if (tab === null) {
    throw new Error(`Tab ${name} not found`)
  }
  activateTab(tab)
}

async function initWallet (): Promise<void> {
  console.debug('initWallet start')
  const creds = await CredentialWithCard.load()
  const walletDiv = getElementById<HTMLDivElement>('wallet-info')

  // Create a MutationObserver instance
  if (observer == null) {
    observer = new MutationObserver((mutationsList) => {
      const emptyWalletDiv = getElementById<HTMLDivElement>('empty-wallet')
      for (const mutation of mutationsList) {
        if (mutation.type === 'childList') {
          emptyWalletDiv.style.display = walletDiv.childNodes.length === 0 ? 'block' : 'none'
        }
      }
    })
    observer.observe(walletDiv, { childList: true })
  }

  walletDiv.replaceChildren()
  creds.forEach((cred) => {
    walletDiv.appendChild(cred.element)
  })

  console.debug('initWallet done')
}

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

const domainPattern = /^(?:(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}|\d{1,3}(?:\.\d{1,3}){3})(?::\d{1,5})?$/

getElementById<HTMLInputElement>('text-import-domain').addEventListener('input', function (event) {
  const value = (event.target as HTMLInputElement).value
  const buttonImportFile = getElementById<HTMLInputElement>('button-import-card')

  const validDomain = domainPattern.test(value)
  if (validDomain) {
    importSettings.domain = value
  }
  buttonImportFile.disabled = !validDomain
  validDomain ? buttonImportFile.classList.remove('config-button-disabled') : buttonImportFile.classList.add('config-button-disabled')
})

getElementById<HTMLInputElement>('dropdown-import-schema').addEventListener('change', function (event) {
  const schema = (event.target as HTMLSelectElement).value
  const textDomain = getElementById<HTMLInputElement>('text-import-domain')
  if (schema === 'mdl_1') {
    const buttonImportFile = getElementById<HTMLInputElement>('button-import-card')
    buttonImportFile.classList.remove('config-button-disabled')
    buttonImportFile.disabled = false
    textDomain.disabled = true
    textDomain.value = '<none>'
    importSettings.domain = 'MDL'
  }
  else {
    textDomain.disabled = false
    textDomain.value = ''
  }
})

listener.handle(MSG_BACKGROUND_POPUP_IS_OPEN, (): true => {
  return true
}, true)

listener.handle(MSG_BACKGROUND_POPUP_PREPARE_STATUS, async (id: string, progress: number) => {
  const card = CredentialWithCard.get(id)
  if (card == null) {
    throw new Error('Card is null')
  }
  card.progress = progress
})

listener.handle(MSG_BACKGROUND_POPUP_PREPARED, async (credUid: string) => {
  const card = CredentialWithCard.get(credUid)
  if (card == null) {
    throw new Error('Card is null')
  }
  card.progress = 100
  card.element.progress.label = 'Prepared'
  setTimeout(() => {
    card.status = 'PREPARED'
  }, PREPARED_MESSAGE_DURATION)
})

listener.handle(MSG_BACKGROUND_POPUP_ACTIVE_TAB_UPDATE, () => {
  void scanForDisclosureRequest()
})

listener.handle(MSG_BACKGROUND_POPUP_ERROR, async (error: string) => {
  console.error('MSG_BACKGROUND_POPUP_ERROR', error)
})

void init().then(() => {
  // Messages can arrive before the initialization is complete. We queue them until init is done
  listener.go()

  /*
    Query the active tab for a disclosure request metadata
  */
  void scanForDisclosureRequest()
})
