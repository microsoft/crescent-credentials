/*
 *  Copyright (c) Microsoft Corporation.
 *  Licensed under the MIT license.
 */

/* eslint-disable @typescript-eslint/no-magic-numbers */

import { MSG_WALLET_UPDATED } from './constants.js'
import { addData, getData } from './indexeddb.js'
import { decodeJwt } from './jwt.js'
import { listen } from './listen.js'
import { fields, decode as mdocDecode } from './mdoc.js'

export type Card_status = 'PENDING' | 'PREPARING' | 'PREPARED' | 'ERROR' | 'DISCLOSABLE' | 'DISCLOSING'

type Token =
  | { type: 'MDOC', value: MDOC }
  | { type: 'JWT', value: JWT_TOKEN }

export interface Card {
  data: string
  token: Token
  issuer: {
    url: string
    name: string
  }
  status: Card_status
  progress: number
  credUid: string
  id: number
}

export class Card implements Card {
  // eslint-disable-next-line @typescript-eslint/max-params
  private constructor (issuerUrl: string, issuerName: string, data: string, token: MDOC | JWT_TOKEN) {
    this.issuer = {
      url: issuerUrl,
      name: issuerName
    }
    this.token = Card.type(token)
  }

  issuer: { url: string, name: string }
  token: Token
  status: Card_status = 'PENDING'

  progress = 0
  credUid = ''

  id = 0

  // eslint-disable-next-line @typescript-eslint/class-methods-use-this
  public async save (): Promise<boolean> {
    return await Wallet.save()
  }

  public static async import (domain: string, encoded: string): Promise<RESULT<Card, Error>> {
    if (typeof encoded !== 'string') {
      return { ok: false, error: new Error('encoded is not a string') }
    }

    if (typeof domain !== 'string') {
      return { ok: false, error: new Error('domain is not a string') }
    }

    let type: 'JWT' | 'MDOC' = 'JWT'

    let token: RESULT<JWT_TOKEN | MDOC, Error> = decodeJwt(encoded)
    if (!token.ok) {
      type = 'MDOC'
      token = mdocDecode(encoded)
    }

    if (!token.ok) {
      return { ok: false, error: new Error('Cannot decode data into JWT or MDOC') }
    }

    if (type === 'MDOC') {
      console.log('MDOC:', fields(token.value as MDOC))
    }

    const card = new Card(domain, domain, encoded, token.value)

    return { ok: true, value: card }
  }

  public static type (card: MDOC | JWT_TOKEN): Token {
    if ('documents' in card) {
      return { type: 'MDOC', value: card }
    }

    return { type: 'JWT', value: card }
  }
}

// eslint-disable-next-line @typescript-eslint/no-extraneous-class
export class Wallet {
  private static _instance: Wallet | null = null

  private static _nextCardId = 0
  private static _onUpdated: (() => void) | null = null

  private constructor () {
    // do nothing
  }

  private static readonly _cards: Card[] = []

  public static get cards (): Card[] {
    return Wallet._cards
  }

  public static async init (): Promise<Wallet> {
    if (Wallet._instance != null) {
      throw new Error('Wallet already initialized')
    }
    Wallet._instance = new Wallet()
    const cards = await getData<Card[]>('crescent', 'jwts') ?? []

    Wallet._nextCardId = cards.length > 0 ? cards.sort((a, b) => a.id - b.id)[0].id + 1 : 0
    Wallet._cards.push(...cards)

    listen(MSG_WALLET_UPDATED, async () => {
      await Wallet.reload()
      if (Wallet._onUpdated !== null) {
        Wallet._onUpdated()
      }
    })

    return Wallet._instance
  }

  public static async reload (): Promise<Wallet> {
    if (Wallet._instance === null) {
      throw new Error('Wallet not initialized')
    }
    const cards = await getData<Card[]>('crescent', 'jwts') ?? []

    Wallet._cards.length = 0

    Wallet._nextCardId = cards.length > 0 ? cards.sort((a, b) => a.id - b.id)[0].id + 1 : 0
    Wallet._cards.push(...cards)
    return Wallet._instance
  }

  public static async add (card: Card): Promise<void> {
    if (Wallet._instance === null) {
      throw new Error('Wallet not initialized')
    }
    card.id = Wallet._nextCardId++
    Wallet._cards.push(card)
    await Wallet.save()
    void chrome.runtime.sendMessage({ action: MSG_WALLET_UPDATED, data: null })
  }

  public static async remove (id: number): Promise<void> {
    if (Wallet._instance === null) {
      throw new Error('Wallet not initialized')
    }
    const index = Wallet._cards.findIndex(c => c.id === id)

    if (index !== -1) {
      Wallet._cards.splice(index, 1)
      await Wallet.save()
      void chrome.runtime.sendMessage({ action: MSG_WALLET_UPDATED, data: null })
    }
  }

  public static find (id: number): Card | undefined {
    return Wallet._cards.find(c => c.id === id)
  }

  public static async save (): Promise<boolean> {
    if (Wallet._instance === null) {
      throw new Error('Wallet not initialized')
    }
    return await addData<Card[]>('crescent', 'jwts', Wallet._cards).catch((_error) => {
      throw new Error('Failed to store cards')
    })
  }

  public static get onUpdated (): ((() => void) | null) {
    return Wallet._onUpdated
  }

  public static set onUpdated (callback: () => void) {
    Wallet._onUpdated = callback
  }

  public static filter (property: string): Card[] {
    return Wallet._cards.filter((card) => {
      if (card.token.type === 'JWT') {
        return card.token.value.payload[property] !== undefined
      }
      // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
      else if (card.token.type === 'MDOC') {
        return fields(card.token.value)[property] !== undefined
      }
      return false
    })
  }
}
