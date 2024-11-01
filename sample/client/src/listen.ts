/*
 *  Copyright (c) Microsoft Corporation.
 *  Licensed under the MIT license.
 */

import { AWAIT_ASYNC_RESPONSE } from './constants.js'

export const ready = false

export function listen<T> (message: string, handler: (data: T & { tabId: number }) => unknown): void {
  chrome.runtime.onMessage.addListener((message1: MESSAGE_PAYLOAD, sender, _sendResponse) => {
    const _tabId = sender.tab?.id
    const action = message1.action
    const data = message1.data as T & { tabId: number }

    if (action === message) {
      data.tabId = _tabId ?? -1
      const result = handler(data)
      if (result instanceof Promise) {
        void result.then((value: unknown) => {
          _sendResponse(value)
        })
        return AWAIT_ASYNC_RESPONSE
      }
      else {
        return result
      }
    }
  })
}
