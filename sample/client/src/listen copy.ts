// /* eslint-disable @typescript-eslint/no-magic-numbers */
// /*
//  *  Copyright (c) Microsoft Corporation.
//  *  Licensed under the MIT license.
//  */

// import { AWAIT_ASYNC_RESPONSE } from './constants.js'

// export let ready = false

// interface HandlerQueueItem<T> {
//   message: string
//   handler: (data: T) => unknown
// }

// const msgQueue: Array<{ message: MESSAGE_PAYLOAD, sender: chrome.runtime.MessageSender, sendResponse: (response: unknown) => void }> = []

// // eslint-disable-next-line @typescript-eslint/no-explicit-any
// const handlerQueue: Array<HandlerQueueItem<any>> = []

// chrome.runtime.onMessage.addListener((message: MESSAGE_PAYLOAD, sender, sendResponse) => {
//   msgQueue.push({ message, sender, sendResponse })
// })

// export function listen<T> (message: string, handler: (data: T & { id?: number }) => unknown): void {
//   handlerQueue.push({ message, handler })

//   chrome.runtime.onMessage.addListener((message1: MESSAGE_PAYLOAD, sender, _sendResponse) => {
//     const _tabId = sender.tab?.id ?? -1
//     const action = message1.action
//     const data = message1.data as T & { tabId: number }
//     // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
//     if (data == null) {
//       console.error(message1)
//     }

//     if (action === message) {
//       console.debug('listen:', message)
//       data.tabId = _tabId
//       const result = handler(data)
//       if (result instanceof Promise) {
//         void result.then((value: unknown) => {
//           _sendResponse(value)
//         })
//         return AWAIT_ASYNC_RESPONSE
//       }
//       else {
//         return result
//       }
//     }
//   })
// }

// function processQueue (): void {
//   for (const { message, sender, sendResponse } of msgQueue) {
//     const action = message.action
//     const data = message.data
//     const tabId = sender.tab?.id ?? -1
//     data.tabId = tabId

//     for (const { message: handlerMessage, handler } of handlerQueue) {
//       if (action === handlerMessage) {
//         console.debug('processQueue:', action)
//         const result = handler(data)
//         if (result instanceof Promise) {
//           void result.then((value: unknown) => {
//             sendResponse(value)
//           })
//           return AWAIT_ASYNC_RESPONSE
//         }
//         else {
//           sendResponse(result)
//           return
//         }
//       }
//     }
//   }
// }

// export function start (): void {
//   ready = true
// }
