/* eslint-disable @typescript-eslint/no-magic-numbers */
/*
 *  Copyright (c) Microsoft Corporation.
 *  Licensed under the MIT license.
 */

import { AWAIT_ASYNC_RESPONSE } from './constants.js'

export const ready = false

export function listen<T> (message: string, handler: (data: T & { tabId: number }) => unknown): void {
  console.debug('listener registered', message)
  chrome.runtime.onMessage.addListener((message1: MESSAGE_PAYLOAD, sender, _sendResponse) => {
    console.debug('listen', message1, sender)

    const _tabId = sender.tab?.id ?? -1
    const action = message1.action
    const data = message1.data as T & { tabId: number }
    // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
    if (data == null) {
      console.error(message1)
    }

    if (action === message) {
      data.tabId = _tabId
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
