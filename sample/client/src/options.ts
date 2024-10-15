/*
*  Copyright (c) Microsoft Corporation.
*  Licensed under the MIT license.
*/

import { MESSAGE_SAMPLE } from './constants.js'

console.debug('options.js: load')

void (async () => {
  const response: unknown = await chrome.runtime.sendMessage({ action: MESSAGE_SAMPLE, data: 'options.js: message' })
  console.debug(response)
})()
