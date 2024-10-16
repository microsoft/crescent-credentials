/*
 *  Copyright (c) Microsoft Corporation.
 *  Licensed under the MIT license.
 */

// export interface JWT { header: Record<string, unknown>, payload: Record<string, unknown>, signature: string }

export function decodeJwt (token: string): JWT {
  const [header, payload, signature] = token.split('.')

  const base64UrlToString = (base64Url: string): string => {
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/')
    const decodedData = decodeURIComponent(
      atob(base64)
        .split('')
        // eslint-disable-next-line @typescript-eslint/no-magic-numbers
        .map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
        .join('')
    )
    return decodedData
  }

  const decodedHeader = JSON.parse(base64UrlToString(header))
  const decodedPayload = JSON.parse(base64UrlToString(payload))

  return {
    header: decodedHeader,
    payload: decodedPayload,
    signature // Signature cannot be decoded, as it's just a cryptographic string
  }
}
