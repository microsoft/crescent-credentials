/*
 *  Copyright (c) Microsoft Corporation.
 *  Licensed under the MIT license.
 */

/* eslint-disable @typescript-eslint/no-magic-numbers */

import { decode as cborDecode } from './cbor.js'

interface mdocDocument {
  docType: string
  deviceSigned: {
    deviceAuth: {
      deviceMac: unknown[]
    }
    nameSpaces: {
      tag: number
      value: Uint8Array
    }
  }
  issuerSigned: {
    issuerAuth: Uint8Array[]
    nameSpaces: Record<string, Array<nameSpace | nameSpaceTag>>
  }
}

interface nameSpaceTag {
  tag: number
  value: Uint8Array
}

interface nameSpace {
  digestID: number
  elementIdentifier: string
  elementValue: unknown
  random: Uint8Array
}

function _bytesToImage (bytes: Uint8Array): HTMLImageElement {
  const blob = new Blob([bytes], { type: 'image/png' })
  const url = URL.createObjectURL(blob)
  const img = document.createElement('img')
  img.src = url
  img.onload = () => {
    URL.revokeObjectURL(url)
  }
  return img
}

function hexToUint8Array (hexString: string): Uint8Array {
  if (hexString.length % 2 !== 0) {
    throw new Error('Invalid hexString')
  }
  if (!/^[0-9a-fA-F]+$/.test(hexString)) {
    throw new Error('Invalid hexString')
  }
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  const hexPairs = hexString.match(/.{1,2}/g)!

  return new Uint8Array(hexPairs.map(byte => parseInt(byte, 16)))
}

export function decode (hex: string): RESULT<MDOC, Error> {
  const bytes = hexToUint8Array(hex)
  const decoded = cborDecode<MDOC>(bytes)

  decoded.documents.forEach((doc: mdocDocument) => {
    (doc.issuerSigned.nameSpaces['org.iso.18013.5.1'] as nameSpaceTag[]).forEach((ns: nameSpaceTag, i) => {
      const decodedTag = cborDecode<nameSpace>(ns.value)
      // decodeElementValue(decodedTag)
      doc.issuerSigned.nameSpaces['org.iso.18013.5.1'][i] = decodedTag
    })
  })

  return { ok: true, value: decoded }
}

function _decodeElementValue (ns: nameSpace): void {
  switch (ns.digestID) {
    case 0:
      ns.elementValue = ns.elementValue as string
      break
    default:
      break
  }
}

export function fields (mdoc: MDOC): Record<string, unknown> {
  const document = mdoc.documents[0]
  const fields: Record<string, unknown> = {}
  document.issuerSigned.nameSpaces['org.iso.18013.5.1'].forEach((ns: nameSpace) => {
    fields[(ns).elementIdentifier] = decodeKnownTags((ns).elementValue)
  })
  return fields
}

function decodeKnownTags (value: unknown): unknown {
  if (typeof value !== 'object') {
    return value
  }

  const obj = value as Record<string, unknown>
  if (!('tag' in obj) || !('value' in obj)) {
    return value
  }

  const tag = obj.tag
  if (!Number.isInteger(tag)) {
    return value
  }

  // switch on the tag value
  switch (tag) {
    case 1004:
      return new Date(`${obj.value as string}T00:00:00Z`)
    default:
      return value
  }
}
