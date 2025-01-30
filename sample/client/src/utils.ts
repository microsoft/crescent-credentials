/*
 *  Copyright (c) Microsoft Corporation.
 *  Licensed under the MIT license.
 */

/* eslint-disable @typescript-eslint/no-magic-numbers */

/**
 * Get an element by its id. The element is expected to exist.
 * Throws an error if the element is not found.
 * @param id {string} Id of the element to get
 * @returns {HTMLElement} The element with the given id
 */
export function getElementById<T> (id: string): T {
  const element = document.getElementById(id)
  if (element == null) {
    throw new Error(`Element with id ${id} not found`)
  }
  return element as T
}

async function _fetch (url: string, params?: Record<string, unknown>, method: 'GET' | 'POST' = 'POST'): Promise<RESULT<Response, Error>> {
  const options: RequestInit = {
    method,
    headers: {
      'Content-Type': 'application/json'
    }
  }

  if (method === 'POST') {
    options.body = JSON.stringify(params)
  }
  else { // GET
    const searchParams = new URLSearchParams(params as Record<string, string>)
    url = `${url}?${searchParams}`
  }

  try {
    const response = await fetch(url, options)

    if (!response.ok) {
      return { ok: false, error: new Error(response.statusText) }
    }

    return { ok: true, value: response }
  }
  catch (error) {
    const typedError = error instanceof Error ? error : new Error(String(error))
    return { ok: false, error: typedError }
  }
}

export async function fetchObject<T> (url: string, params?: Record<string, unknown>, method: 'GET' | 'POST' = 'POST'): Promise<RESULT<T, Error>> {
  const response = await _fetch(url, params, method)
  if (!response.ok) {
    return response
  }
  const json = await response.value.json()
  return { ok: true, value: json as T }
}

export async function fetchText (url: string, params?: Record<string, unknown>, method: 'GET' | 'POST' = 'POST'): Promise<RESULT<string, Error>> {
  const response = await _fetch(url, params, method)
  if (!response.ok) {
    return response
  }
  const text = await response.value.text()
  return { ok: true, value: text }
}

export function base64Decode (base64: string): Uint8Array {
  try {
    base64 = base64.replace(/-/g, '+').replace(/_/g, '/')

    while (base64.length % 4 > 0) {
      base64 += '='
    }
    const binaryString = atob(base64)
    const length = binaryString.length
    const bytes = new Uint8Array(length)

    for (let i = 0; i < length; i++) {
      bytes[i] = binaryString.charCodeAt(i)
    }

    return bytes
  }
  catch (error) {
    throw new Error('Failed to decode base64 string: ' + (error instanceof Error ? error.message : ''))
  }
}

export function guid (): string {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (char) {
    const random = (Math.random() * 16) | 0
    const value = char === 'x' ? random : (random & 0x3) | 0x8
    return value.toString(16)
  })
}

export function assert<T> (value: T | undefined | null): asserts value is T {
  if (value == null) {
    throw new TypeError('Assert: value is not defined')
  }
}

export async function acctiveTabId (): Promise<number> {
  return await new Promise((resolve, _reject) => {
    chrome.tabs.query({ active: true, lastFocusedWindow: true }, (tabs) => {
      resolve(tabs[0]?.id ?? -1)
    })
  })
}

export function isBackground (): boolean {
  // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
  return (typeof window === 'undefined' || window.location?.pathname?.includes('background'))
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export async function messageToActiveTab<T> (action: string, ...data: any[]): Promise<T> {
  const activeTabId = await acctiveTabId()

  if (activeTabId === -1) {
    return undefined as T
  }

  const result = chrome.tabs.sendMessage(activeTabId, { action, data }).catch((error: Error) => {
    if (error.message.includes('Receiving end does not exist.')) {
      const message = `
          If you reload this extension, you also need to refresh the tab(s) to update the injected content script.
          Or you will get this error when sending a message to the tab: 
          %cCould not establish connection. Receiving end does not exist.`
        .trim()
        .replace(/\n\s+/g, '\n')
      console.log(`%c${message}`, 'color: yellow;', 'color: orange; font-weight: bold;')
    }
    else {
      console.error(`${error.message}`)
    }
  })

  return result as T
}

export async function openPopup (): Promise<void> {
  console.log('Opening popup window')
  await chrome.action.openPopup().catch((error) => {
    /*
      If the popup is already open, this error will be thrown:
      "Could not find an active browser window."
    */
    console.warn('Failed to open popup window', error)
  })
}

export async function setBadge (text: string): Promise<void> {
  await chrome.action.setBadgeText({ text })

  setTimeout(() => {
    void chrome.action.setBadgeText({ text: '' }) // Clear the badge
  }, 5000)
}

export function notify (title: string, message: string): void {
  chrome.notifications.create({
    type: 'basic',
    iconUrl: 'icons/icon128.png',
    title,
    message,
    requireInteraction: true
  })
}
