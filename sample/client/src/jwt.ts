/*
 *  Copyright (c) Microsoft Corporation.
 *  Licensed under the MIT license.
 */

import { base64Decode } from './utils'

// export interface JWT { header: Record<string, unknown>, payload: Record<string, unknown>, signature: string }

export function decodeJwt (token: string): RESULT<JWT_TOKEN, Error> {
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

const _publicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwn7A7eGN3lV6I16si2ra
pQRz0ONd1EWBJ4XanO9MkzIg4wpo7DHcbPCxXeCvEee3eR+M4f3yhm357N5ZI/4+
rZyPJ/s7dHb95aS8yL5q5jAvIjoe1U68xvdhDsiE2j7ce/3Mct9zgrAkPerTBRk/
vVnnCbmYd1ewvcl5akAuWsGk70v9ersPx+7mpccLlyQ4nlT/UtLwbas9bez84Pkr
Qqm8xJ0G07qKCbwbnIQ4jil0ek0EJxwESPZ5GrnZlAAp6z5P9JFnQOem1rauobql
hr//i95V3Mh5s1MXp8OMU2ICFIxYL9AHT5kLFkf+k+cFr+NcX93d63dm4Aeo22Ao
bQIDAQAB
-----END PUBLIC KEY-----`

const _privateKey = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDCfsDt4Y3eVXoj
XqyLatqlBHPQ413URYEnhdqc70yTMiDjCmjsMdxs8LFd4K8R57d5H4zh/fKGbfns
3lkj/j6tnI8n+zt0dv3lpLzIvmrmMC8iOh7VTrzG92EOyITaPtx7/cxy33OCsCQ9
6tMFGT+9WecJuZh3V7C9yXlqQC5awaTvS/16uw/H7ualxwuXJDieVP9S0vBtqz1t
7Pzg+StCqbzEnQbTuooJvBuchDiOKXR6TQQnHARI9nkaudmUACnrPk/0kWdA56bW
tq6huqWGv/+L3lXcyHmzUxenw4xTYgIUjFgv0AdPmQsWR/6T5wWv41xf3d3rd2bg
B6jbYChtAgMBAAECggEAAkPeJNcV4yM9NSi+2y/PJJFY9POU7eoyTx7GtUGvM16n
1eUS5D9PaSBjfGuntk5ry1gT+LTPrIOe38SWJq5pFfYHD8jkAB77pX9F6JOZJJ2m
iuBA6CyO08VhRr4MmAsX38TMqwDRtFGvVl5D/2D0JlUj9O/JqAgoKYmtZZCiSZHH
CIzZeGhbLip7FmCDdpjxne9wlJdt8uEMtNg5fdEAAQGXAMw7YLE2rUCLiq8zHVuY
6BUZvKjvevYw67v8j0L6CD0cDDd5G+mmx57LaEbiGe307wVqjNdoJyFOEtNzJaoZ
S4u8aZ1mOaZPZUe8mKq8jS2p1Dfx7f11rIig/lbFkQKBgQD8ZzXf8yuoXyPPZK7N
OTZAMoxuEkFm1gGf7Uq8W2CG/u924dC7Lrx4CFFZ3KuUHzWNBkQ5mU3goOrN4XCi
2EqI8m1jb7A++98IOXToB9k1ikn+SbEBgyP2PQJnxJ+WsqwaCb2uJxQhRLMdegjo
E8EfW4LAxM7FsSMo6xev6Jy2/QKBgQDFREoYv2FBgDfDB9+ydvLYg5QSH0ak6JSK
KwtKJq2/rpt/BtwANANlng/Yu1I2EKHO6ICXpvyhTRey9pImd3EbaEqqKqXZPE8+
AnD5pJmd//aYiOoj4ZTAU4fgj7MwCMWvJF8nscI9vDuxisLG36CraQRIzLD2iodW
MTWPeSxKMQKBgAKB1/Qoizd58nYd7uqU9ef/WIvDXKjz2UJIbiSe17+fiqtopNUn
KrIaiwxUd9PZ14NWG5li33YqwwpWgfLsKRlhJxsEwgBuKhH/2Bxx74Nroz6GZt63
+cR5aKu1NUye67y6egrf0oBeGVVin/IGODXih9L4YYFvOAUxCKQzsFLVAoGBAIPi
7EcvbK6GMsHJ+d0veZ0YG18iWfDXLrhRnvKseW22J2/9/giEveCqlJ2qX4SWChhz
icXadvzAth+Iip39LTnNuF2ctdVPZQtoRnAhhDMGdq/0mdXzc6hCMI4KhRqQQtqd
zqCTT/JGbwJ8a0zbJmhzhdHGSGoMo/8UV2Lc+KeBAoGBAO7u+oUxe2sg9e+ev7rL
XCuJJigqLZPO/MDHWpGoCETJp/GGVC8zumHrFYHXReP+dcz3h6M8kpGiJBSGq8tC
twYFGel8tgXQuVRgqREz1hOmfaI+i0zF3kznQmgsomoYCbFCL8Z53KWNvaCvw9eu
SyFQtMlieKMvjs28XDD7WOEk
-----END PRIVATE KEY-----`

// export async function resignJwt (token: CARD): Promise<CARD> {
//   const privateKey = await importPrivateKey()
//   const headerU8 = objectToUint8Array(token.header)
//   const payloadU8 = objectToUint8Array(token.payload)
//   const data = new Uint8Array(headerU8.length + payloadU8.length)
//   data.set(headerU8)
//   data.set(payloadU8, headerU8.length)
//   const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', privateKey, data)
//   const signatureU8 = new Uint8Array(signature)
//   const newJwt = `${bytesToBase64url(headerU8)}.${bytesToBase64url(payloadU8)}.${bytesToBase64url(signatureU8)}`
//   token.jwt = newJwt
//   token.signature = bytesToBase64url(signatureU8)
//   return token
// }

// async function importPrivateKey (): Promise<CryptoKey> {
//   const pemContents = _privateKey
//     .replace(/-----BEGIN PRIVATE KEY-----/, '')
//     .replace(/-----END PRIVATE KEY-----/, '')
//     .replace(/\s+/g, '')
//   const binaryDerString = self.atob(pemContents)
//   const binaryDer = new Uint8Array(binaryDerString.length)

//
//   for (let i = 0; i < binaryDerString.length; i++) {
//     binaryDer[i] = binaryDerString.charCodeAt(i)
//   }

//   return await crypto.subtle.importKey(
//     'pkcs8',
//     binaryDer.buffer,
//     {
//       name: 'RSASSA-PKCS1-v1_5',
//       hash: { name: 'SHA-256' }
//     },
//     true,
//     ['sign']
//   )
// }

// function objectToUint8Array (obj: Record<string, unknown>): Uint8Array {
//   const jsonString = JSON.stringify(obj)
//   const base64String = btoa(jsonString)
//   const binaryString = self.atob(base64String)
//   const binary = new Uint8Array(binaryString.length)
//
//   for (let i = 0; i < binaryString.length; i++) {
//     binary[i] = binaryString.charCodeAt(i)
//   }
//   return binary
// }

// function bytesToBase64url (bytes: Uint8Array): string {
//   const base64 = btoa(String.fromCharCode(...bytes))
//   return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
// }
