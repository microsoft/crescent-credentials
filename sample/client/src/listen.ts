/*
 *  Copyright (c) Microsoft Corporation.
 *  Licensed under the MIT license.
 */

/* eslint-disable @typescript-eslint/no-magic-numbers */

import { AWAIT_ASYNC_RESPONSE } from './constants.js'

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Handler<T = unknown> = (...args: any[]) => Promise<T> | T

interface Listener {
  handle: <T>(action: string, handler: Handler<T>) => void
  go: () => void
}

type Destinations = 'content' | 'background' | 'popup' | 'offscreen'

const _queue: Array<{ message: MESSAGE_PAYLOAD, sender: chrome.runtime.MessageSender, sendResponse: (response?: unknown) => void }> = []
let _go = false
const _handlers: Record<string, Handler> = {}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export async function sendMessage<T> (destination: string, action: string, ...data: any[]): Promise<T> {
  // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
  console.debug('sendMessage', action, ...data)
  return await chrome.runtime.sendMessage({ destination, action, data }) as T
}

export function setListener (destination: Destinations): Listener {
  console.debug('setListener', destination)
  chrome.runtime.onMessage.addListener((message1: MESSAGE_PAYLOAD, sender, _sendResponse) => {
    if (message1.destination === destination) {
      _queue.push({ message: message1, sender, sendResponse: _sendResponse })
      if (_go) {
        processQueue()
      }
      return AWAIT_ASYNC_RESPONSE
    }
  })
  return {
    handle: (action: string, handler: Handler): void => {
      _handlers[action] = handler
    },
    go: (): void => {
      _go = true
      processQueue()
    }
  }
}

function processQueue (): void {
  while (_queue.length > 0) {
    const { message, sender, sendResponse } = _queue.shift() as { message: MESSAGE_PAYLOAD, sender: chrome.runtime.MessageSender, sendResponse: (response?: unknown) => void }
    const action = message.action
    const data = message.data
    const _tabId = sender.tab?.id ?? -1
    const handler = _handlers[action] as Handler | undefined
    if (handler != null) {
      const result = handler(...data, sender)
      if (result instanceof Promise) {
        void result.then((value: unknown) => {
          sendResponse(value)
        })
      }
      else {
        sendResponse(result)
      }
    }
    else {
      console.error('No handler for', action)
    }
  }
}
