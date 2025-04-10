/*
 *  Copyright (c) Microsoft Corporation.
 *  Licensed under the MIT license.
 */

/* eslint-disable @typescript-eslint/no-magic-numbers */

import { LitElement, html, css, type TemplateResult, unsafeCSS } from 'lit'
import { unsafeHTML } from 'lit/directives/unsafe-html.js'
import { property } from 'lit/decorators.js'
import { assert, getElementById } from '../utils'
import type { Card_status, CredentialWithCard } from '../cred'
import 'dotenv/config'
import './collapsible.js'
import myConfig from '../config'

export class CardElement extends LitElement {
  private _ready = false
  private readonly _status: Card_status = 'PENDING'
  private readonly _progress = 0
  public _disclosureParams: { verifierUrl: string, disclosureValues: string[], disclosureUid: string, disclosureChallenge: string, proofSpec: string } | null = null

  @property({ type: Object })
  private _credential: CredentialWithCard | null = null

  static styles = css`
        .container {
            border-radius: 8px;
            box-shadow: 0px 4px 8px rgba(0, 0, 0, 0.4);
            padding: 20px;
            margin-bottom: 10px;
            background: linear-gradient(-45deg, color-mix(in srgb, black 50%, ${unsafeCSS(myConfig.cardColor)}), ${unsafeCSS(myConfig.cardColor)});
        }

        .button {
            width: 100px;
            border-radius: 5px;
            border: 1px solid #ccc;
            box-shadow: 0px 4px 8px rgba(0, 0, 0, 0.1);
            padding: 5px;
        }

        button:hover {
            cursor: pointer;
        }

        p {
            color: #F0F0F0;
            font-size: 18px;
            text-shadow: 1px 1px 2px rgba(0, 0, 0, 0.2);
            margin: 8px;
        }

        table { 
          border-collapse: collapse;
          font-size: 10px;
        }

        #info {
          font-size: 26px;
          color: #EEEEEE;
          font-weight: bold;
          display: flex;
          justify-content: space-between;
          align-items: center;
          text-shadow: 1px 1px 2px rgba(0, 0, 0, 0.7);
        }

        #error {
          margin: 20px 0;
          display: none;
        }

        #progress {
            margin: 20px 0;
            display: none;
        }

        #disclose{
            margin: 20px 0;
            display: none;
        }

        #discloseVerifierLabel {
        }

        .disclosePropertyLabel {
            font-weight: bold;
        }

        #prepareProgress {
            width: 100%;
            height: 10px;
            accent-color: #73FBFD;
        }

        #error {
            margin: 20px 0;
            display: none;
        }

        #buttonDelete {
            background: none;
            border: none;
            padding: 0;
            cursor: pointer;
        }

        #buttonDisclose {
            padding: 8px;
            border-radius: 8px;
            border: 1px solid black;
            width: 100px;
            box-shadow: 0px 4px 8px rgba(0, 0, 0, 0.3);
        }

        .even {
            background: #f0f0f0;
        }

        .odd {
            background: #ffffff;
        }

        td {
            padding: 5px;
        }
  `

  // The render method to display the content
  render (): TemplateResult {
    assert (this._credential)
    const credRecord = this._credential.data

    return html`
      <div class="container">

        <div id="info">
          <span>${credRecord.issuer.name}</span>
          <button id="buttonDelete" @click=${this._credential.delete.bind(this._credential)}>
            <img src="../icons/x.svg" width="15" alt="delete card"/>
          </button>
        </div>

        <div id="progress">
          <p id="progressLabel">Preparing ...</p>
          <progress id="prepareProgress" max="100"></progress>
        </div>

        <div id="disclose">
          <p>Disclose</p>
          <div id="discloseProperties"></div>
          <p id="discloseVerifierLabel"></p>
          <button id="buttonDisclose" @click=${this._handleDisclose.bind(this)}>Disclose</button>
        </div>

        <div id="consent">
          <p>${credRecord.issuer.name} would like to add a credential to your wallet</p>
          <div style="display: flex; justify-content: center; gap: 10px;">
            <button class='button' id="walletItemAccept" @click=${this._credential.accept.bind(this._credential)}>Accept</button>
            <button class='button' id="walletItemReject" @click=${this._credential.delete.bind(this._credential)}>Reject</button>
          </div>
        </div>

        <div id="error">
          <p>Import failed</p>
          <p id="errorMessage">Import failed</p>
          <button id="buttonErrorClose" @click=${this._handleReject.bind(this)}>Cancel</button>
        </div>

        <c2pa-collapsible>
          <span slot="header">&nbsp;</span>
          <div slot="content">
            ${unsafeHTML(this.jsonToTable(credRecord.token.fields))}
          </div>
        </c2pa-collapsible>

      </div>
    `
  }

  firstUpdated (): void {
    this._ready = true
    this._configureFromState()
  }

  // eslint-disable-next-line @typescript-eslint/class-methods-use-this
  private jsonToTable (json: Record<string, unknown>): string {
    let i = 0
    const table = ['<table class="table">'].concat(Object.keys(json).map((key) => {
      return `<tr class="table-row ${i++ % 2 === 0 ? 'even' : 'odd'}"><td class="key">${key}</td><td class="value">${json[key] as string}</td></tr>`
    }))
    table.push('</table>')
    return table.join('')
  }

  private _configureFromState (): void {
    assert(this._credential)

    const status = this._credential.status
    this.buttons.hide()
    this.progress.hide()
    this.disclose.hide()

    if (status === 'PENDING') {
      this.buttons.show()
    }
    else if (status === 'PREPARING') {
      this.progress.label = 'Preparing ...'
      this.progress.value = this._credential.progress
      this.progress.show()
    }
    else if (status === 'PREPARED') {
      // nothing to do
    }
    else if (status === 'DISCLOSABLE') {
      this.disclose.show()
    }
  }

  error (message: string): void {
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const errorElement = this.shadowRoot!.querySelector<HTMLDivElement>('.error')!
    this.progress.hide()
    this.buttons.hide()
    errorElement.style.display = 'block';
    (getElementById<HTMLDivElement>('errorMessage')).innerText = message
  }

  // eslint-disable-next-line @typescript-eslint/max-params
  discloseRequest (verifierUrl: string, disclosureValues: string[], disclosureUid: string, disclosureChallenge: string, proofSpec: string): void {
    assert(this.shadowRoot)
    const discloseProperties = this.shadowRoot.querySelector<HTMLParagraphElement>('#discloseProperties')
    assert(discloseProperties)
    const discloseVerifierLabel = this.shadowRoot.querySelector<HTMLParagraphElement>('#discloseVerifierLabel')
    assert(discloseVerifierLabel)

    disclosureValues.forEach((value) => {
      const disclosePropertyLabel = document.createElement('p')
      disclosePropertyLabel.className = `disclosePropertyLabel`
      disclosePropertyLabel.innerText = `${value}`
      discloseProperties.appendChild(disclosePropertyLabel)
    })

    discloseVerifierLabel.innerText = `to ${verifierUrl.replace(/^.*?:\/\/([^/:?#]+).*$/, '$1')}?`
    this._disclosureParams = { verifierUrl, disclosureValues, disclosureUid, disclosureChallenge, proofSpec }
  }

  get progress (): { show: () => void, hide: () => void, value: number, label: string } {
    assert(this.shadowRoot)
    const progressSection = this.shadowRoot.querySelector<HTMLDivElement>('#progress')
    assert(progressSection)
    const progressControl = this.shadowRoot.querySelector<HTMLProgressElement>('#prepareProgress')
    assert(progressControl)
    const progressLabel = this.shadowRoot.querySelector<HTMLProgressElement>('#progressLabel')
    assert(progressLabel)

    return {
      show: () => {
        progressSection.style.display = 'block'
      },
      hide: () => {
        progressSection.style.display = 'none'
      },
      get value () {
        return progressControl.value
      },
      set value (val: number) {
        progressControl.value = val
      },
      // eslint-disable-next-line accessor-pairs
      set label (val: string) {
        progressLabel.innerText = val
      }
    }
  }

  get buttons (): { show: () => void, hide: () => void } {
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const buttonsElement = this.shadowRoot!.querySelector<HTMLDivElement>('#consent')!
    return {
      show: () => {
        buttonsElement.style.display = 'block'
      },
      hide: () => {
        buttonsElement.style.display = 'none'
      }
    }
  }

  get disclose (): { show: () => void, hide: () => void } {
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const discloseSection = this.shadowRoot!.querySelector<HTMLDivElement>('#disclose')!
    return {
      show: () => {
        discloseSection.style.display = 'block'
      },
      hide: () => {
        discloseSection.style.display = 'none'
      }
    }
  }

  private _handleReject (): void {
    assert(this._credential)
    this._credential.reject()
  }

  private _handleDisclose (): void {
    assert(this._credential)
    assert(this._disclosureParams?.verifierUrl)
    assert(this._disclosureParams.disclosureUid)
    assert(this._disclosureParams.disclosureChallenge)
    assert(this._disclosureParams.proofSpec)
    this._credential.disclose(this._disclosureParams.verifierUrl, this._disclosureParams.disclosureUid, this._disclosureParams.disclosureChallenge, this._disclosureParams.proofSpec)
  }

  get credential (): CredentialWithCard {
    assert(this._credential)
    return this._credential
  }

  set credential (credential: CredentialWithCard) {
    if (credential !== this._credential) {
      this._credential = credential

      this._credential.onStatusChange = (_status: Card_status) => {
        this._configureFromState()
      }

      this._credential.onProgressChange = (progress: number) => {
        this.progress.value = progress
      }
    }
  }
}

// Register the custom element
customElements.define('card-element', CardElement)
