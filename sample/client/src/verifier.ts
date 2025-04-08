/*
*  Copyright (c) Microsoft Corporation.
*  Licensed under the MIT license.
*/

import { assert, isBackground, messageToActiveTab } from './utils'
import { Credential } from './cred'
import config from './config'
import { MSG_BACKGROUND_CONTENT_SEND_PROOF, MSG_POPUP_BACKGROUND_DISCLOSE } from './constants'
import { sendMessage, setListener } from './listen'
import init, { create_show_proof_wasm } from 'crescent'
import { fetchShowProof } from './clientHelper'

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

// eslint-disable-next-line @typescript-eslint/max-params
async function handleDisclose (id: string, destinationUrl: string, disclosureUid: string, challenge: string, proofSpec: string): Promise<void> {
  const cred = Credential.get(id)
  assert(cred)

  console.debug('Disclosing credential', cred.id, destinationUrl, disclosureUid, challenge, proofSpec)

  let showProof: string | null = null

  if (config.wasmShowProof) {
    await init(/* wasm module */)
    const showParams = cred.data.showData as ClientHelperShowResponse
    showProof = create_show_proof_wasm(
      showParams.client_state_b64,
      showParams.range_pk_b64,
      showParams.io_locations_str,
      disclosureUid,
      challenge
    ).replace('show_proof_b64: ', '').replace(/"/g, '')
    assert(showProof)
  }
  else {
    // TODO: remove this when fixed in issuer
    const result = await fetchShowProof(cred.id, disclosureUid, challenge, (proofSpec === 'e30') ? 'eyJyZXZlYWxlZCI6W119' : proofSpec)
    if (!result.ok) {
      console.error('Failed to fetch show data:', result.error)
      return
    }
    showProof = result.value
    assert(showProof)
  }

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

// eslint-disable-next-line @typescript-eslint/max-params
export async function disclose (cred: Credential, verifierUrl: string, disclosureUid: string, challenge: string, proofSpec: string): Promise<void> {
  void sendMessage('background', MSG_POPUP_BACKGROUND_DISCLOSE, cred.id, verifierUrl, disclosureUid, challenge, proofSpec)
}

// if this is running the the extension background service worker, then listen for messages
if (isBackground()) {
  const listener = setListener('background')
  listener.handle(MSG_POPUP_BACKGROUND_DISCLOSE, handleDisclose)
}
