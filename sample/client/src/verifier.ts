/*
*  Copyright (c) Microsoft Corporation.
*  Licensed under the MIT license.
*/

import { assert, fetchText, isBackground, messageToActiveTab } from './utils'
import { Credential } from './cred'
import config from './config'
import { MSG_BACKGROUND_CONTENT_SEND_PROOF, MSG_POPUP_BACKGROUND_DISCLOSE } from './constants'
import { sendMessage, setListener } from './listen'
import init, { create_show_proof_wasm } from 'crescent'

export interface ClientHelperShowResponse {
  client_state_b64: string
  range_pk_b64: string
  io_locations_str: string
}

export type ShowProof = string

// required for wasm now()
declare global {
  // eslint-disable-next-line @typescript-eslint/naming-convention, no-unused-vars
  function js_now_seconds (): bigint
}
globalThis.js_now_seconds = (): bigint => BigInt(Math.floor(Date.now() / 1000))

export async function show (cred: Credential, disclosureUid: string, challenge: string): Promise<RESULT<ShowProof, Error>> {
  const response = await fetchText(`${config.clientHelperUrl}/show`, { cred_uid: cred.id, disc_uid: disclosureUid, challenge }, 'GET')
  if (!response.ok) {
    console.error('Failed to show:', response.error)
    return response
  }
  return response
}

async function handleDisclose (id: string, destinationUrl: string, disclosureUid: string, challenge: string): Promise<void> {
  const cred = Credential.get(id)
  assert(cred)

  await init(/* wasm module */)

  const showParams = cred.data.showData as ClientHelperShowResponse

  const showProof = create_show_proof_wasm(
    showParams.client_state_b64,
    showParams.range_pk_b64,
    showParams.io_locations_str,
    disclosureUid,
    challenge
  ).replace('show_proof_b64: ', '').replace(/"/g, '')
  assert(showProof)

  const params = {
    url: destinationUrl,
    disclosure_uid: disclosureUid,
    issuer_url: cred.data.issuer.url,
    schema_uid: cred.data.token.schema,
    session_id: challenge,
    proof: showProof
  }

  void messageToActiveTab(MSG_BACKGROUND_CONTENT_SEND_PROOF, params)
}

export async function disclose (cred: Credential, verifierUrl: string, disclosureUid: string, challenge: string): Promise<void> {
  void sendMessage('background', MSG_POPUP_BACKGROUND_DISCLOSE, cred.id, verifierUrl, disclosureUid, challenge)
}

// if this is running the the extension background service worker, then listen for messages
if (isBackground()) {
  const listener = setListener('background')
  listener.handle(MSG_POPUP_BACKGROUND_DISCLOSE, handleDisclose)
}
