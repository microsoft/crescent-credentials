/*
 *  Copyright (c) Microsoft Corporation.
 *  Licensed under the MIT license.
 */

import { base64Decode } from './utils'

export function decode (token: string): RESULT<JWT_TOKEN, Error> {
  const [headerB64, payloadB64, signatureB64] = token.split('.')
  const decoder = new TextDecoder('utf-8')
  try {
    return { ok: true, value: {
      header: JSON.parse(decoder.decode(base64Decode(headerB64))),
      payload: JSON.parse(decoder.decode(base64Decode(payloadB64))),
      signature: signatureB64
    } }
  }
  catch (error) {
    return { ok: false, error: new Error('cannot base64 decode jwt string') }
  }
}

export function fields (jwt: JWT_TOKEN): Record<string, unknown> {
  return jwt.payload
}
