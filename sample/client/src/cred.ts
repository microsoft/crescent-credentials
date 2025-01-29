/*
 *  Copyright (c) Microsoft Corporation.
 *  Licensed under the MIT license.
 */

import { fields as mdocFields } from './mdoc'
import { fields as jwtFields } from './jwt'
import schemas, { type Schema } from './schema'
import type { CardElement } from './components/card'
import { assert, guid } from './utils'
import { sendMessage } from './listen'
import { addData, getData, removeData } from './indexeddb.js'
import * as clientHelper from './clientHelper'
import * as verifier from './verifier'
import { MSG_POPUP_BACKGROUND_UPDATE } from './constants'

export interface CredentialRecord {
  token: {
    type: 'JWT' | 'MDOC'
    schema: string
    raw: string
    value: JWT_TOKEN | MDOC
    fields: Record<string, unknown>
  }
  issuer: {
    url: string
    name: string
  }
  status: Card_status
  credUid: string
  progress: number
}

export type Card_status = 'PENDING' | 'PREPARING' | 'PREPARED' | 'ERROR' | 'DISCLOSABLE' | 'DISCLOSING'

export type clientUid = string

export class Credential {
  public data: CredentialRecord

  public static creds: Credential[] = []

  public static async load (): Promise<Credential[]> {
    // eslint-disable-next-line @typescript-eslint/non-nullable-type-assertion-style
    const credData = await getData('crescent') as Array<{ id: string, data: CredentialRecord }>
    this.creds = credData.map(cred => new Credential(cred.data))
    return this.creds
  }

  public static get (credUid: string): Credential | undefined {
    const cred = Credential.creds.find(cred => cred.id === credUid)
    return cred
  }

  constructor (credential: CredentialRecord)
  constructor (domain: string, schemaName: string, rawJwtOrMdoc: string)
  constructor (
    credentialOrDomain: CredentialRecord | string, schemaName?: string, rawJwtOrMdoc?: string) {
    if (typeof credentialOrDomain !== 'string') {
      this.data = credentialOrDomain
      return
    }

    if (typeof credentialOrDomain !== 'string') {
      throw new TypeError('domain is not a string')
    }

    if (typeof schemaName !== 'string') {
      throw new TypeError('schemaName is not a string')
    }

    if (typeof rawJwtOrMdoc !== 'string') {
      throw new TypeError('rawJwtOrMdoc is not a string')
    }

    const schema = schemas[schemaName] as Schema | undefined
    if (schema == null) {
      throw new Error(`Unknown schema ${schemaName}`)
    }

    const decoded = schema.decode(rawJwtOrMdoc)
    if (!decoded.ok) {
      throw new Error(`Failed to decode ${schemaName}: ${decoded.error.message}`)
    }

    this.data = {
      token: {
        type: schema.type,
        schema: schema.name,
        raw: rawJwtOrMdoc,
        value: decoded.value,
        fields: schema.type === 'JWT' ? jwtFields(decoded.value as JWT_TOKEN) : mdocFields(decoded.value as MDOC)
      },
      issuer: {
        url: credentialOrDomain.startsWith('http') ? credentialOrDomain : `http://${credentialOrDomain}`,
        name: credentialOrDomain.replace(/^https?:\/\//, '').replace(/:\d+$/, '')
      },
      status: 'PENDING',
      credUid: guid(),
      // eslint-disable-next-line @typescript-eslint/no-magic-numbers
      progress: 0
    }
  }

  public async save (): Promise<boolean> {
    const result = await addData('crescent', this.id, this.data)
    void sendMessage('background', MSG_POPUP_BACKGROUND_UPDATE)
    return result
  }

  public get status (): Card_status {
    return this.data.status
  }

  public set status (status: Card_status) {
    this.data.status = status
  }

  public get progress (): number {
    return this.data.progress
  }

  public set progress (progress: number) {
    this.data.progress = progress
  }

  public get id (): string {
    return this.data.credUid
  }
}

export class CredentialWithCard extends Credential {
  // eslint-disable-next-line @typescript-eslint/prefer-readonly
  private _element: CardElement
  private _onProgressChangeCallback?: (progress: number) => void
  private _onStatusChangeCallback?: (status: Card_status) => void

  public static creds: CredentialWithCard[] = []

  public static async load (): Promise<CredentialWithCard[]> {
    // eslint-disable-next-line @typescript-eslint/non-nullable-type-assertion-style
    const credData = await getData('crescent') as Array<{ id: string, data: CredentialRecord }>
    this.creds = credData.map(cred => new CredentialWithCard(cred.data))
    return this.creds
  }

  public static get (credUid: string): CredentialWithCard | undefined {
    const cred = CredentialWithCard.creds.find(cred => cred.id === credUid)
    return cred
  }

  constructor (card: CredentialRecord) {
    super(card)
    this._element = document.createElement('card-element') as CardElement
    this._element.credential = this
  }

  public get progress (): number {
    return this.data.progress
  }

  public set progress (progress: number) {
    this.data.progress = progress
    this._onProgressChangeCallback?.(progress)
  }

  public async accept (): Promise<void> {
    const newCredUid = await clientHelper.prepare(this)
    /*
      Prepare returns a new credUid assigned by client helper
      We will use this as the new id for this credential
    */
    this.data.credUid = newCredUid
    this.status = 'PREPARING'
    void this.save()
  }

  public reject (): void {
    assert(this.element.parentElement)
    this.element.parentElement.removeChild(this.element)
    void removeData('crescent', this.id).then(async () => {
      await CredentialWithCard.load()
    })
  }

  public delete (): void {
    this.reject()
    void clientHelper.remove(this)
  }

  public get element (): CardElement {
    return this._element
  }

  // eslint-disable-next-line accessor-pairs
  public set onProgressChange (callback: (progress: number) => void) {
    this._onProgressChangeCallback = callback
  }

  // eslint-disable-next-line accessor-pairs
  public set onStatusChange (callback: (status: Card_status) => void) {
    this._onStatusChangeCallback = callback
  }

  public get status (): Card_status {
    return this.data.status
  }

  public set status (status: Card_status) {
    this.data.status = status
    this._onStatusChangeCallback?.(status)
  }

  public discloserRequest (url: string, disclosureUid: string, challenge: string): void {
    if (this.status !== 'PREPARED') {
      return
    }
    const disclosureProperty = this.getDisclosureProperty(disclosureUid)
    if (disclosureProperty === null) {
      return
    }
    this.element.discloseRequest(url, disclosureProperty, disclosureUid, challenge)
    this.status = 'DISCLOSABLE'
  }

  public disclose (url: string, disclosureUid: string, challenge: string): void {
    void verifier.disclose(this, url, disclosureUid, challenge)
    this.status = 'PREPARED'
    window.close()
  }

  private getDisclosureProperty (uid: string): string | null {
    switch (uid) {
      case 'crescent://email_domain':
        // eslint-disable-next-line no-case-declarations, @typescript-eslint/no-unnecessary-condition
        const emailValue = this.data.token.fields.email as string | undefined
        return emailValue === undefined ? null : emailValue.replace(/^.*@/, '')

      case 'crescent://over_18':
        // eslint-disable-next-line no-case-declarations, @typescript-eslint/no-unnecessary-condition
        const dob = this.data.token.fields.birth_date as string | undefined
        return dob === undefined ? null : 'age is over 18'

      default:
        return null
    }
  }
}
