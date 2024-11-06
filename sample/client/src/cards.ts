/*
 *  Copyright (c) Microsoft Corporation.
 *  Licensed under the MIT license.
 */

/* eslint-disable @typescript-eslint/no-magic-numbers */

import { MSG_WALLET_UPDATED } from './constants.js'
import { addData, getData } from './indexeddb.js'
import { listen } from './listen.js'
import { fields } from './mdoc.js'
import schemas from './schema.js'

export type Card_status = 'PENDING' | 'PREPARING' | 'PREPARED' | 'ERROR' | 'DISCLOSABLE' | 'DISCLOSING'

interface Token {
  type: 'MDOC' | 'JWT'
  schema: string
  value: MDOC | JWT_TOKEN
}

export interface ICard {
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

export class Card implements ICard {
  // eslint-disable-next-line @typescript-eslint/max-params
  constructor (card: ICard) {
    this.data = card.data
    this.token = card.token
    this.issuer = card.issuer
    this.status = card.status
    this.progress = card.progress
    this.credUid = card.credUid
    this.id = card.id
  }

  public readonly data: string
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

  public static async import (domain: string, schemaName: string, encoded: string): Promise<RESULT<Card, Error>> {
    if (typeof encoded !== 'string') {
      return { ok: false, error: new Error('encoded is not a string') }
    }

    if (typeof domain !== 'string') {
      return { ok: false, error: new Error('domain is not a string') }
    }

    // let type: 'JWT' | 'MDOC' = 'JWT'

    const schema = schemas[schemaName]
    const decoded = schema.decode(encoded)

    if (!decoded.ok) {
      return { ok: false, error: new Error(`Cannot decode data into ${schema.type}`) }
    }

    const cardObj: ICard = {
      data: encoded,
      token: {
        type: schema.type,
        schema: schema.name,
        value: decoded.value
      },
      issuer: {
        url: domain.startsWith('http') ? domain : `http://${domain}`,
        name: domain.replace(/^https?:\/\//, '').replace(/:\d+$/, '')
      },
      status: 'PENDING',
      progress: 0,
      credUid: '',
      id: 0
    }

    const card = new Card(cardObj)

    return { ok: true, value: card }
  }

  public static type (card: MDOC | JWT_TOKEN): Token {
    if ('documents' in card) {
      return { type: 'MDOC', schema: 'mdl_1', value: card }
    }

    return { type: 'JWT', schema: 'jwt_corporate_1', value: card }
  }
}

// eslint-disable-next-line @typescript-eslint/no-extraneous-class
export class Wallet {
  private static _instance: Wallet | null = null

  private static _nextCardId = 0
  private static _onUpdated: (() => void) | null = null
  private static _onReady: (() => void) | null = null

  private constructor () {
    // do nothing
  }

  private static readonly _cards: Card[] = []

  public static get initialized (): boolean {
    return Wallet._instance !== null
  }

  public static get cards (): Card[] {
    return Wallet._cards
  }

  private static _id = ''

  public static async init (id: string): Promise<Wallet> {
    console.debug('Wallet: init', id)
    Wallet._id = id

    if (Wallet._instance != null) {
      throw new Error('Wallet already initialized')
    }

    Wallet._instance = new Wallet()

    const cards = await getData<Card[]>('crescent', 'jwts') ?? []

    Wallet._nextCardId = cards.length > 0 ? cards.sort((a, b) => a.id - b.id)[0].id + 1 : 0
    Wallet._cards.push(...cards.map(card => new Card(card)))

    console.debug('Wallet.cards:', Wallet._cards)

    listen(MSG_WALLET_UPDATED, async () => {
      await Wallet.reload()
      if (Wallet._onUpdated !== null) {
        Wallet._onUpdated()
      }
    })

    if (Wallet._onReady !== null) {
      console.debug('Wallet init onReady callback')
      Wallet._onReady()
    }

    return Wallet._instance
  }

  // eslint-disable-next-line accessor-pairs
  public static set onReady (callback: () => void) {
    if (Wallet._instance !== null) {
      console.debug('Wallet already ready callback')
      callback()
    }
    Wallet._onReady = callback
  }

  public static async reload (): Promise<Wallet | null> {
    Wallet.checkWalletInitialized()
    const cards = await getData<Card[]>('crescent', 'jwts') ?? []

    Wallet._cards.length = 0

    Wallet._nextCardId = cards.length > 0 ? cards.sort((a, b) => a.id - b.id)[0].id + 1 : 0
    Wallet._cards.push(...cards.map(card => new Card(card)))

    return Wallet._instance
  }

  public static async add (card: Card): Promise<void> {
    Wallet.checkWalletInitialized()
    card.id = Wallet._nextCardId++
    Wallet._cards.push(card)
    await Wallet.save()
    void chrome.runtime.sendMessage({ action: MSG_WALLET_UPDATED, data: {} }).catch((_error) => {
      console.warn('NO LISTENER', MSG_WALLET_UPDATED)
    })
  }

  public static async remove (id: number): Promise<void> {
    Wallet.checkWalletInitialized()
    const index = Wallet._cards.findIndex(c => c.id === id)

    if (index !== -1) {
      Wallet._cards.splice(index, 1)
      await Wallet.save()
      void chrome.runtime.sendMessage({ action: MSG_WALLET_UPDATED, data: {} }).catch((_error) => {
        console.warn('NO LISTENER', MSG_WALLET_UPDATED)
      })
    }
  }

  public static find (id: number): Card | undefined {
    return Wallet._cards.find(c => c.id === id)
  }

  public static async save (): Promise<boolean> {
    Wallet.checkWalletInitialized()
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
        return (card.token.value as JWT_TOKEN).payload[property] !== undefined
      }
      // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
      else if (card.token.type === 'MDOC') {
        return fields(card.token.value as MDOC)[property] !== undefined
      }
      return false
    })
  }

  private static checkWalletInitialized (): void {
    if (Wallet._instance === null) {
      throw new Error(`Wallet not initialized ${Wallet._id}`)
    }
  }
}
