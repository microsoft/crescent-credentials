import { LitElement, html, css, type TemplateResult } from 'lit'
import { unsafeHTML } from 'lit/directives/unsafe-html.js'
import { property } from 'lit/decorators.js'
import { getElementById } from '../utils'
import './collapsible.js'
import { fields } from '../mdoc'
import type { Card, Card_status } from '../cards'

// type WalletEntryState = 'consent' | 'preparing' | 'prepared' | 'disclosing' | 'disclosed' | 'error' | 'idle'

export class CardElement extends LitElement {
  // Define properties for domain and email

  // Optional styles for the component
  static styles = css`
        .container {
            border-radius: 8px;
            box-shadow: 0px 4px 8px rgba(0, 0, 0, 0.3);
            padding: 20px;
            margin-bottom: 10px;
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
            color: white;
            font-size: 16px;
        }

        table { 
          border-collapse: collapse;
          font-size: 10px;
        }

        #info {
          font-size: 20px;
          font-weight: bold;
          display: flex;
          justify-content: space-between;
          align-items: center;
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

        #disclosePropertyLabel {
            font-weight: bold;
        }

        #prepareProgress {
            width: 100%;
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
  @property({ type: Object, reflect: true }) card = null as Card | null
  @property({ type: Function }) accept?: (card: Card) => void
  @property({ type: Function }) reject?: (card: Card) => void
  @property({ type: Function }) disclose?: (card: Card) => void
  @property({ type: Function }) delete?: (card: Card) => void

  private _cardColor (): void {
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const container = this.shadowRoot!.querySelector<HTMLDivElement>('#container')! //
    container.style.setProperty('background-color', '#809071')
  }

  // The render method to display the content
  render (): TemplateResult {
    const card = this.card
    if (card == null) {
      return html`<div>Card is null</div>`
    }

    const color = `#${(Math.floor(200 - (Math.random() * 60))).toString(16)}${(Math.floor(200 - (Math.random() * 60))).toString(16)}${(Math.floor(200 - (Math.random() * 60))).toString(16)}`

    return html`
      <div class="container" style="background-color:${color}">

        <div id="info">
          <span>${card.issuer.name}</span>
          <button id="buttonDelete" @click=${this._handleDelete.bind(this)}>
            <img src="../icons/trash.svg" width="15" alt="trashcan icon"/>
          </button>
        </div>

        <div id="progress">
          <p id="progressLabel">Preparing ...</p>
          <progress id="prepareProgress" max="100"></progress>
        </div>

        <div id="disclose">
          <p>Disclose</p>
          <p id="disclosePropertyLabel"></p>
          <p id="discloseVerifierLabel"></p>
          <button id="buttonDisclose" @click=${this._handleDisclose.bind(this)}>Disclose</button>
        </div>

        <div id="consent">
          <p>${card.issuer.name} would like to add credentials to your wallet</p>
          <div style="display: flex; justify-content: center; gap: 10px;">
            <button class='button' id="walletItemAccept" @click=${this._handleAccept.bind(this)}>Accept</button>
            <button class='button' id="walletItemReject" @click=${this._handleReject.bind(this)}>Reject</button>
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
            ${unsafeHTML(this.jsonToTable(card.token.type === 'JWT' ? (card.token.value).payload : fields(card.token.value)))}
          </div>
        </c2pa-collapsible>

      </div>
    `
  }

  private _state: Card_status = 'PENDING'

  get status (): Card_status {
    return this._state
  }

  set status (state: Card_status) {
    this._state = state
    if (this._ready) {
      this._configureFromState()
    }
  }

  private _ready = false

  firstUpdated (): void {
    // super.connectedCallback()
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
    if (this._state === 'PENDING') {
      this.progress.hide()
      this.buttons.show()
    }
    else if (this._state === 'PREPARING') {
      this.progress.label = 'Preparing ...'

      this.progress.value = this.card?.progress ?? 0
      this.buttons.hide()
      this.progress.show()
    }
    else if (this._state === 'PREPARED') {
      this.buttons.hide()
      this.progress.hide()
    }
    else if (this._state === 'DISCLOSABLE') {
      this.buttons.hide()
      this.progress.hide()
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      const discloseSection = this.shadowRoot!.querySelector<HTMLDivElement>('#disclose')!
      discloseSection.style.display = 'block'
    }
  }

  error (message: string): void {
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const errorElement = this.shadowRoot!.querySelector<HTMLDivElement>('.error')!
    this.progress.hide()
    this.buttons.hide()
    errorElement.style.display = 'block';
    (getElementById('errorMessage') as HTMLParagraphElement).innerText = message
  }

  discloseRequest (verifierUrl: string, disclosureValue: string, disclosureUid: string): void {
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const disclosePropertyLabel = this.shadowRoot!.querySelector<HTMLParagraphElement>('#disclosePropertyLabel')!
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const discloseVerifierLabel = this.shadowRoot!.querySelector<HTMLParagraphElement>('#discloseVerifierLabel')!
    disclosePropertyLabel.innerText = `${disclosureUid.replace('crescent://', '')} : ${disclosureValue}`
    discloseVerifierLabel.innerText = `to ${verifierUrl}?`
  }

  get progress (): { show: () => void, hide: () => void, value: number, label: string } {
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const progressSection = this.shadowRoot!.querySelector<HTMLDivElement>('#progress')!
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const progressControl = this.shadowRoot!.querySelector<HTMLProgressElement>('#prepareProgress')!
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const progressLabel = this.shadowRoot!.querySelector<HTMLProgressElement>('#progressLabel')!
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

  private _handleAccept (): void {
    if (this.accept != null && this.card != null) {
      this.status = 'PREPARING'
      this.accept(this.card)
    }
  }

  private _handleReject (): void {
    if (this.reject != null && this.card != null) {
      this.reject(this.card)
    }
  }

  private _handleDisclose (): void {
    if (this.disclose != null && this.card != null) {
      this.status = 'DISCLOSING'
      this.disclose(this.card)
      window.close()
    }
  }

  private _handleDelete (): void {
    if (this.delete != null && this.card != null) {
      this.delete(this.card)
    }
  }
}

// Register the custom element
customElements.define('card-element', CardElement)
