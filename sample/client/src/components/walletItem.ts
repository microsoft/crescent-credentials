import { LitElement, html, css, type TemplateResult } from 'lit'
import { property } from 'lit/decorators.js'

export class WalletItem extends LitElement {
  // Define properties for domain and email

  // Optional styles for the component
  static styles = css`
    .container {
      font-family: Arial, sans-serif;
      padding: 8px;
      border: 1px solid #ddd;
      border-radius: 4px;
      width: fit-content;
    }
    .domain {
      font-size: 18px;
      font-weight: bold;
      color: #333;
    }
    .email {
      font-size: 14px;
      color: #666;
    }
  `

  @property({ type: String, reflect: true }) domain = ''
  @property({ type: String, reflect: true }) email = ''

  // The render method to display the content
  render (): TemplateResult {
    return html`
      <div class="container">
        <div class="domain">${this.domain}</div>
        <div class="email">${this.email}</div>
      </div>
    `
  }
}

// Register the custom element
customElements.define('domain-email', WalletItem)
