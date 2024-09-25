/*
 *  Copyright (c) Microsoft Corporation.
 *  Licensed under the MIT license.
 */

/* eslint-disable @typescript-eslint/no-magic-numbers */

import { AWAIT_ASYNC_RESPONSE, MESSAGE_SAMPLE } from './constants.js'

console.debug('background.js: load')

chrome.runtime.onInstalled.addListener((details) => {
    if (details.reason === 'install') {
        console.debug('background.js: install')
    }
    else if (details.reason === 'update') {
        console.debug('background.js: update')
    }
})

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    const tabId = sender.tab?.id
    const action = message.action

    /*

    For async response, use the following pattern:

        if (action === MESSAGE_SAMPLE) {
            ayncCall(params).then(sendResponse).catch(sendResponse)
            return AWAIT_ASYNC_RESPONSE
        }

    For sync response, use the following pattern:

        if (action === MESSAGE_SAMPLE) {
            sendResponse(syncCall())
            return
        }

    */
})

async function init(): Promise<void> {
    // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
    if (chrome.offscreen !== undefined) {
        if (await chrome.offscreen.hasDocument()) {
            return
        }

        await chrome.offscreen
            .createDocument({
                url: 'offscreen.html',
                reasons: [chrome.offscreen.Reason.DOM_PARSER],
                justification: 'Private DOM access to parse HTML'
            })
            .catch((error) => {
                console.error('Failed to create offscreen document', error)
            })
    }
}

void init()
