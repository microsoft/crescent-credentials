/*
 *  Copyright (c) Microsoft Corporation.
 *  Licensed under the MIT license.
 */

/* eslint-disable @typescript-eslint/no-magic-numbers */

import {
  MSG_BACKGROUND_POPUP_ERROR, MSG_BACKGROUND_POPUP_PREPARE_STATUS, MSG_BACKGROUND_POPUP_PREPARED,
  MSG_POPUP_BACKGROUND_DELETE, MSG_POPUP_BACKGROUND_PREPARE
} from './constants'
import config from './config'
import { assert, isBackground } from './utils'
import { type clientUid, Credential } from './cred'
import { sendMessage, setListener } from './listen'
import { removeData } from './indexeddb'

async function _prepare (issuerUrl: string, jwt: string, schemaUid: string): Promise<RESULT<string, Error>> {
  const options = {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      issuer_url: issuerUrl,
      cred: jwt,
      schema_uid: schemaUid
    })
  }

  const response = await fetch(`${config.clientHelperUrl}/prepare`, options).catch((error) => {
    return { text: () => `ERROR: ${error}` }
  })

  const credUid = await response.text()

  if (credUid.startsWith('ERROR')) {
    return { ok: false, error: new Error(credUid) }
  }

  return { ok: true, value: credUid }
}

export async function fetchPrepareStatus (credUid: string, progress: () => void): Promise<RESULT<string, Error>> {
  return await new Promise((resolve) => {
    const intervalId = setInterval(
      // eslint-disable-next-line @typescript-eslint/no-misused-promises
      async () => {
        const response = await fetch(`${config.clientHelperUrl}/status?cred_uid=${credUid}`).catch((error) => {
          return { text: () => `Error: ${error.message}` }
        })

        const status = await response.text()

        if (status === 'unknown' || status.startsWith('Error:')) {
          clearInterval(intervalId)
          resolve({ ok: false, error: new Error(status) })
        }

        if (status === 'ready') {
          clearInterval(intervalId)
          resolve({ ok: true, value: credUid })
        }

        progress()
      }, config.pollInterval)
  })
}

async function _deleteCred (credUid: string): Promise<boolean> {
  const response = await fetch(`${config.clientHelperUrl}/delete?cred_uid=${credUid}`).catch((_error) => {
    console.error('Failed to delete cred:', credUid)
    return { ok: false }
  })
  return response.ok
}

export async function ping (url: string): Promise<boolean> {
  const response = await fetch(`${url}/status?cred_uid=ping`).catch((_error) => {
    console.error('Failed to ping:', url)
    return { ok: false }
  })
  return response.ok
}

async function pollStatus (cred: Credential): Promise<void> {
  let progress = 0
  const credUid = cred.id

  const result = await fetchPrepareStatus (credUid,
    () => {
      progress = Math.ceil((100 - progress) * 0.05) + progress
      cred.progress = progress
      void cred.save().then(() => {
        void sendMessage('popup', MSG_BACKGROUND_POPUP_PREPARE_STATUS, credUid, progress)
      })
    }
  )

  if (result.ok) {
    cred.progress = 100
    cred.status = 'PREPARED'
    await cred.save()
    await Credential.load()
    void sendMessage('popup', MSG_BACKGROUND_POPUP_PREPARED, credUid)
  }
  else {
    console.error('Failed to prepare:', result.error)
    cred.status = 'ERROR'
    await cred.save()
    void sendMessage('popup', MSG_BACKGROUND_POPUP_ERROR, credUid)
  }
}

export async function prepare (cred: Credential): Promise<clientUid> {
  const result = await sendMessage<RESULT<string, Error>>('background', MSG_POPUP_BACKGROUND_PREPARE, cred.id)
  if (!result.ok) {
    throw new Error(result.error.message)
  }
  const newCredUid = result.value
  return newCredUid
}

async function handlePrepare (id: string): Promise<RESULT<string, Error>> {
  const cred = Credential.get(id)
  assert(cred)

  const result = await _prepare(cred.data.issuer.url, cred.data.token.raw, cred.data.token.schema)
  if (!result.ok) {
    return { ok: false, error: { message: 'Prepare failed. Check Client-Helper service.', name: 'Error' } }
  }

  // Update the credUid and save to storage as a new entry
  cred.data.credUid = result.value
  cred.status = 'PREPARING'
  await cred.save()

  // Remove the old entry
  await removeData('crescent', id)

  void pollStatus(cred)

  return result
}

export async function remove (cred: Credential): Promise<void> {
  // Client helper will have no record of this credential if it is still in PENDING status
  if (['PENDING', 'PREPARING'].includes(cred.status)) {
    return
  }
  void sendMessage('background', MSG_POPUP_BACKGROUND_DELETE, cred.id)
}

async function handleRemove (id: string): Promise<void> {
  const cred = Credential.get(id)
  assert(cred)
  void _deleteCred(cred.id)
}

// if this is running the the extension background service worker, then listen for messages
if (isBackground()) {
  const listener = setListener('background')
  listener.handle(MSG_POPUP_BACKGROUND_PREPARE, handlePrepare)
  listener.handle(MSG_POPUP_BACKGROUND_DELETE, handleRemove)
}
