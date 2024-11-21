/*
*  Copyright (c) Microsoft Corporation.
*  Licensed under the MIT license.
*/

import { assert, fetchText, isBackground, messageToActiveTab } from './utils'
import { Credential } from './cred'
import config from './config'
import { MSG_BACKGROUND_CONTENT_SEND_PROOF, MSG_POPUP_BACKGROUND_DISCLOSE } from './constants'
import { sendMessage, setListener } from './listen'

export interface ClientHelperShowResponse {
  client_state_b64: string
  range_pk_b64: string
  io_locations_str: string
}

export type ShowProof = string

export async function show (cred: Credential, disclosureUid: string): Promise<RESULT<ShowProof, Error>> {
  const response = await fetchText(`${config.clientHelperUrl}/show`, { cred_uid: cred.id, disc_uid: disclosureUid }, 'GET')
  if (!response.ok) {
    console.error('Failed to show:', response.error)
    return response
  }
  return response
}

async function handleDisclose (id: string, destinationUrl: string, disclosureUid: string): Promise<void> {
  const cred = Credential.get(id)
  assert(cred)

  const showProof = await show(cred, disclosureUid)
  if (!showProof.ok) {
    console.error('Failed to show proof:', showProof.error)
    return
  }

  const params = {
    url: destinationUrl,
    disclosure_uid: disclosureUid,
    issuer_url: cred.data.issuer.url,
    schema_uid: cred.data.token.schema,
    proof: showProof.value
  }

  void messageToActiveTab(MSG_BACKGROUND_CONTENT_SEND_PROOF, params)
}

export async function disclose (cred: Credential, verifierUrl: string, disclosureUid: string): Promise<void> {
  void sendMessage('background', MSG_POPUP_BACKGROUND_DISCLOSE, cred.id, verifierUrl, disclosureUid)
}

// if this is running the the extension background service worker, then listen for messages
if (isBackground()) {
  const listener = setListener('background')
  listener.handle(MSG_POPUP_BACKGROUND_DISCLOSE, handleDisclose)
}
