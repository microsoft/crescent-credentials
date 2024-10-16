/*
 *  Copyright (c) Microsoft Corporation.
 *  Licensed under the MIT license.
 */

import type { ToggleSwitch } from './components/toggle.js'
import type { WalletItem } from './components/walletItem.js'
import { MSG_POPUP_DISPLAY_JWTS } from './constants.js'
import { getData } from './indexeddb.js'
import { getElementById } from './utils.js'

console.debug('popup.js: load')

document.addEventListener('DOMContentLoaded', function (): void {
  // Add event listeners to switch tabs
  const tabs = document.querySelectorAll<HTMLButtonElement>('.tab')
  tabs.forEach((tab) => {
    tab.addEventListener('click', () => {
      activateTab(tab)
    })
  })

  const toggle1 = document.getElementById('toggle1') as ToggleSwitch
  toggle1.addEventListener('change', (event) => {
    const _checked = (event as CustomEvent).detail.checked as boolean
    // do stuff
  })

  const toggle2 = document.getElementById('toggle2') as ToggleSwitch
  toggle2.addEventListener('change', (event) => {
    const _checked = (event as CustomEvent).detail.checked as boolean
    // do stuff
  })

  void displayJwts ()
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

// eslint-disable-next-line @typescript-eslint/no-unused-vars
async function _sendBackgroundMessage<T> (type: string, data: unknown): Promise<T> {
  return await chrome.runtime.sendMessage({ type, data })
}

chrome.runtime.onMessage.addListener((request: MESSAGE_PAYLOAD, _sender, _sendResponse) => {
  if (request.action === MSG_POPUP_DISPLAY_JWTS) {
    showTab('wallet')
  }
})

function showTab (name: string): void {
  const tab = document.querySelector<HTMLButtonElement>(`button[data-tab="${name}"`)
  if (tab === null) {
    throw new Error(`Tab ${name} not found`)
  }
  activateTab(tab)
}

async function displayJwts (): Promise<void> {
  const jwts = await getData<JWT_RECORDS>('crescent', 'jwts')
  if (jwts === undefined) {
    // no records
    return
  }
  const walletContent = document.getElementById('wallet-info')
  jwts.forEach((jwt) => {
    console.log('jwt:', jwt)
    const jwtElement = document.createElement('domain-email') as WalletItem
    jwtElement.domain = jwt.url
    jwtElement.email = (jwt.jwt.payload.email as string | undefined) ?? '<undefined>'
    jwtElement.onclick = disclose
    walletContent?.appendChild(jwtElement)
  })
}

async function disclose (evt: Event): Promise<void> {
  const target = evt.target as WalletItem
  console.log('disclose:', target.domain)

  const response = await fetch('http://127.0.0.1:8004/verify', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ proof: 'proof', issuer: target.domain })
  }).catch((error) => {
    console.error('Error:', error)
    return { json: () => {
      console.log('')
    } }
  })
  const data = await response.json()
  console.log('response:', data)
}
