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
export function getElementById (id: string): HTMLElement {
  const element = document.getElementById(id)
  if (element == null) {
    throw new Error(`Element with id ${id} not found`)
  }
  return element
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
// eslint-disable-next-line @typescript-eslint/naming-convention, @typescript-eslint/max-params
function _postToURL (tabId: number, url: string, issuer_URL: string, schema_UID: string, proof: string): void {
  const formHtml = `
      <form id="postForm" action="${url}" method="POST" style="display: none;">
          <input type="hidden" name="issuer_URL" value="${issuer_URL}">
          <input type="hidden" name="schema_UID" value="${schema_UID}">
          <input type="hidden" name="proof" value="${proof}">
      </form>
      <script>
          document.getElementById('postForm').submit();
      </script>
  `

  void chrome.scripting.executeScript({
    target: { tabId },
    func: (formHtml) => {
      console.log('Injecting form:', formHtml)
      const formContainer = document.createElement('div')
      formContainer.innerHTML = formHtml
      document.body.appendChild(formContainer)
    },
    args: [formHtml]
  })
}
