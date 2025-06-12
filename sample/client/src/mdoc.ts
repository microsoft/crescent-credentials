/*
 *  Copyright (c) Microsoft Corporation.
 *  Licensed under the MIT license.
 */

/* eslint-disable @typescript-eslint/no-magic-numbers */

import { decode as cborDecode } from './cbor.js'
import { base64Decode } from './utils.js'

export interface mdocDocument {
  docType: string
  namespaces: Record<string, Array<nameSpace | nameSpaceTag>>
  mso: Record<string, unknown>
  issuerAuth: unknown[]
  devicePrivateKey?: string
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

export function decode (json: string): RESULT<mdocDocument, Error> {
  try {
    const obj: { mdoc: string, devicePrivateKey?: string } = JSON.parse(json)
    const u8mdoc = base64Decode(obj.mdoc)
    const decoded = cborDecode<mdocDocument>(u8mdoc);
    (decoded.namespaces['org.iso.18013.5.1'] as nameSpaceTag[]).forEach((ns: nameSpaceTag, i) => {
      const decodedTag = cborDecode<nameSpace>(ns.value)
      decoded.namespaces['org.iso.18013.5.1'][i] = decodedTag
    })
    // eslint-disable-next-line @typescript-eslint/strict-boolean-expressions
    decoded.devicePrivateKey = obj.devicePrivateKey && atob(obj.devicePrivateKey)
    return { ok: true, value: decoded }
  }
  catch (e) {
    return { ok: false, error: new Error('Invalid JSON input') }
  }
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

export function fields (mdoc: mdocDocument): Record<string, unknown> {
  const fields: Record<string, unknown> = {}
  Object.values(mdoc.namespaces).flat().forEach((ns: nameSpace | nameSpaceTag) => {
    fields[(ns as nameSpace).elementIdentifier] = decodeKnownTags((ns as nameSpace).elementValue)
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
