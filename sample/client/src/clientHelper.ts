/*
 *  Copyright (c) Microsoft Corporation.
 *  Licensed under the MIT license.
 */

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

        if (status === 'unknown' || status.startsWith('Error:')) {
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

export async function deleteCred (credUid: string): Promise<boolean> {
  const response = await fetch(`${config.client_helper_url}/delete?cred_uid=${credUid}`).catch((_error) => {
    console.error('Failed to delete cred:', credUid)
    return { ok: false }
  })
  return response.ok
}

export async function show (card: Card, disclosureUid: string): Promise<RESULT<ShowProof, Error>> {
  const response = await fetchText(`${config.client_helper_url}/show`, { cred_uid: card.credUid, disc_uid: disclosureUid }, 'GET')
  if (!response.ok) {
    console.error('Failed to show:', response.error)
    return response
  }
  return response
}

export async function ping (url: string): Promise<boolean> {
  const response = await fetch(`${url}/status?cred_uid=ping`).catch((_error) => {
    console.error('Failed to ping:', url)
    return { ok: false }
  })
  return response.ok
}
