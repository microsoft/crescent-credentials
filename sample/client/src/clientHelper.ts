/*
 *  Copyright (c) Microsoft Corporation.
 *  Licensed under the MIT license.
 */

import type { Card } from './cards'
import config from './config'
import { fetchText } from './utils'

const PREPARE_POLL_INTERVAL = parseInt(process.env.PREPARE_POLL_INTERVAL ?? '5000')

export interface ClientHelperShowResponse {
  client_state_b64: string
  range_pk_b64: string
  io_locations_str: string
}

export type ShowProof = string

export async function prepare (issuerUrl: string, jwt: string, schemaUid: string): Promise<RESULT<string, Error>> {
  const options = {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      issuer_URL: issuerUrl,
      cred: jwt,
      schema_UID: schemaUid
    })
  }

  const response = await fetch(`${config.client_helper_url}/prepare`, options).catch((error) => {
    return { text: () => `ERROR: ${error}` }
  })

  const credUid = await response.text()

  if (credUid.startsWith('ERROR')) {
    return { ok: false, error: new Error(credUid) }
  }

  return { ok: true, value: credUid }
}

export async function status (credUid: string, progress: () => void): Promise<RESULT<string, Error>> {
  return await new Promise((resolve) => {
    const intervalId = setInterval(
      // eslint-disable-next-line @typescript-eslint/no-misused-promises
      async () => {
        const response = await fetch(`${config.client_helper_url}/status?cred_uid=${credUid}`).catch((error) => {
          return { text: () => `Error: ${error.message}` }
        })

        const status = await response.text()

        if (status === 'error' || status.startsWith('Error:')) {
          clearInterval(intervalId)
          resolve({ ok: false, error: new Error(status) })
        }

        if (status === 'ready') {
          clearInterval(intervalId)
          resolve({ ok: true, value: credUid })
        }

        progress()
      }, PREPARE_POLL_INTERVAL)
  })
}

export async function show (card: Card): Promise<RESULT<ShowProof, Error>> {
  const response = await fetchText(`${config.client_helper_url}/show`, { cred_uid: card.credUid, disc_uid: 'crescent://email_domain' }, 'GET')
  if (!response.ok) {
    return response
  }
  return response
}

export async function ping (url: string): Promise<boolean> {
  const response = await fetch(`${url}/status?cred_uid=ping`).catch((_error) => {
    return { ok: false }
  })
  return response.ok
}