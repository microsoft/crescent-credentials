/*
 *  Copyright (c) Microsoft Corporation.
 *  Licensed under the MIT license.
 */

/* eslint-disable @typescript-eslint/no-magic-numbers */

import { AWAIT_ASYNC_RESPONSE, DEBUG } from './constants.js'

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type HandlerFunction<T = unknown> = (...args: any[]) => Promise<T> | T

interface Handler {
  func: HandlerFunction
  windowOnly: boolean
}

interface Listener {
  handle: <T>(action: string, handler: HandlerFunction<T>, windowOnl?: boolean) => void
  go: () => void
}

type Destinations = 'content' | 'background' | 'popup'

const _queue: Array<{ message: MESSAGE_PAYLOAD, sender: chrome.runtime.MessageSender, sendResponse: (response?: unknown) => void }> = []
let _go = false
const _handlers: Record<string, Handler> = {}
const _listeners: Record<string, Listener | undefined> = {}
let thisWindowId: number | null = null

async function getWindowId (): Promise<number | null> {
  return await new Promise((resolve, _reject) => {
    // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
    if (chrome.windows == null) {
      resolve(null)
      return
    }
    chrome.windows.getCurrent((window) => {
      resolve(window.id ?? -1)
    })
  })
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export async function sendMessage<T> (destination: string, action: string, ...data: any[]): Promise<T> {
  // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
  console.debug('sendMessage', action, ...data)
  const windowId = await getWindowId()
  return await chrome.runtime.sendMessage({ destination, action, data, windowId }).catch ((error: Error) => {
    if (error.message.includes('Receiving end does not exist.')) {
      DEBUG && console.log(`%cNo listener for ${action}`, 'color: yellow;')
      DEBUG && console.log(`%cThis is expected for some messages to Popup if it is closed.`, 'color: gray;')
    }
    else {
      console.error(`${error.message}`)
    }
    return undefined as T
  })
}

export function setListener (destination: Destinations): Listener {
  console.debug('setListener', destination)

  if (_listeners[destination] != null) {
    return _listeners[destination]
  }

  chrome.runtime.onMessage.addListener((message1: MESSAGE_PAYLOAD, sender, _sendResponse) => {
    if (message1.destination === destination) {
      _queue.push({ message: message1, sender, sendResponse: _sendResponse })
      if (_go) {
        processQueue()
      }
      return AWAIT_ASYNC_RESPONSE
    }
  })
  const listener = {
    handle: (action: string, handler: HandlerFunction, windowOnly = false): void => {
      _handlers[action] = { func: handler, windowOnly }
    },
    go: (): void => {
      _go = true
      void getWindowId().then((windowId) => {
        thisWindowId = windowId
        processQueue()
      })
    }
  }
  _listeners[destination] = listener
  return listener
}

function processQueue (): void {
  while (_queue.length > 0) {
    const { message, sender, sendResponse } = _queue.shift() as { message: MESSAGE_PAYLOAD, sender: chrome.runtime.MessageSender, sendResponse: (response?: unknown) => void }
    const action = message.action
    const data = message.data
    const senderWindowId = message.windowId
    const _tabId = sender.tab?.id ?? -1
    const handler = _handlers[action] as Handler | undefined
    if (handler == null) {
      console.error('No handler for', action)
      continue
    }
    // Don't process if windowId is set and doesn't match the current window
    if (handler.windowOnly && senderWindowId !== thisWindowId) {
      continue
    }
    const result = handler.func(...data, sender)
    if (result instanceof Promise) {
      void result.then((value: unknown) => {
        sendResponse(value)
      })
    }
    else {
      sendResponse(result)
    }
  }
}
