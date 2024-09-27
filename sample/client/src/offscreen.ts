/*
*  Copyright (c) Microsoft Corporation.
*  Licensed under the MIT license.

*/

import { MESSAGE_SAMPLE } from './constants.js'

console.debug('offscreen.js: load')

void (async () => {
    const response: unknown = await chrome.runtime.sendMessage({ action: MESSAGE_SAMPLE, data: 'offscreen.js: message' })
    console.debug(response)
})()
