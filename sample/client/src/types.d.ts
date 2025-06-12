/*
 *  Copyright (c) Microsoft Corporation.
 *  Licensed under the MIT license.
 */

/* eslint-disable no-unused-vars */

/*
  put global types here
  if you using build:watch, you may need to restart it after adding new types here or it may not recognize them
  TODO: add this to rollup watch files
  We use all-caps for global types to distinguish them from imported and local types
*/

interface MESSAGE_PAYLOAD {
  destination: 'content' | 'background' | 'popup'
  routed: boolean
  action: string
  windowId: number | null
  data: unknown[]
}

declare module 'crescent' {
  // eslint-disable-next-line @typescript-eslint/max-params, @typescript-eslint/naming-convention
  export function create_show_proof_wasm (
    clientStateB64: string,
    rangePkB64: string,
    ioLocationsStr: string,
    disclosureUid: string,
    challenge: string,
    proofSpec: string,
    devicePrivateKeyB64?: string
  ): string

  export default function init (): Promise<void>
}

interface JWT_TOKEN { header: Record<string, unknown>, payload: Record<string, unknown>, signature: string }

interface MDOC { status: number, version: string, documents: mdocDocument[] }

type RESULT<T, E = Error> =
  | { ok: true, value: T }
  | { ok: false, error: E }
