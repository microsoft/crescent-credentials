/*
 *  Copyright (c) Microsoft Corporation.
 *  Licensed under the MIT license.
 */

import { LitElement, html, css, type TemplateResult } from 'lit'
import { customElement, property } from 'lit/decorators.js'

const sharedStyles = css`
    :host {
        --background: #FFFFFF;
        --border-color: #DDDDDD;
        --background-highlight: #F4F4F4;
        --border-radius: 5px;
        --font-family: 'Roboto', Arial, Helvetica, sans-serif;
        --font-size: 14px;
        --font-bold: 700;
    }`

@customElement('c2pa-collapsible')
export class C2paCollapsible extends LitElement {
  @property({ type: Boolean }) open = false

  static styles = [
    sharedStyles,
    css`
    .collapsible-container {

    }
    .collapsible-header {
      cursor: pointer;
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-weight: 700;
      font-size: 16px;
    }
    .collapsible-content {
      overflow: hidden;
      max-height: 0;
      transition: max-height 0.3s ease;
      background: #E0E0E0;
      padding: 0px;
      border-radius: 5px;
    }
    .collapsible-content.open  {
      max-height: 400px;
    }
    .icon {
      transition: transform 0.3s ease;
      width: 12px; 
      height: 12px;
      transform-origin: center;
      display: inline-block;
      transform: rotate(90deg);
    }
    .rotated {
      transform: rotate(180deg);
    }
    
  `]

  toggle = (): void => {
    this.open = !this.open
    this.requestUpdate()
    console.log(this.open)
  }

  render (): TemplateResult {
    return html`
      <div class="collapsible-container">
        <div class="collapsible-header" @click="${this.toggle}">
          ${this.open ? this.renderIcon('open') : this.renderIcon('closed')}
          <span class="section-title"><slot name="header">Default Header</slot></span>
        </div>
        <div class="collapsible-content ${this.open ? 'open' : ''}">
          <slot name="content">Default Content</slot>
        </div>
      </div>
    `
  }

  // eslint-disable-next-line @typescript-eslint/class-methods-use-this
  renderIcon (state: 'open' | 'closed'): TemplateResult {
    const iconClass = state === 'open' ? 'icon rotated' : 'icon'
    return html`<svg class="${iconClass}" viewBox="0 0 512 512">
      <g id="Page-1" stroke="none" stroke-width="1" fill="none" fill-rule="evenodd">
          <g id="drop" fill="#D0D0D0" transform="translate(32.000000, 42.666667)">
              <path d="M246.312928,5.62892705 C252.927596,9.40873724 258.409564,14.8907053 262.189374,21.5053731 L444.667042,340.84129 C456.358134,361.300701 449.250007,387.363834 428.790595,399.054926 C422.34376,402.738832 415.04715,404.676552 407.622001,404.676552 L42.6666667,404.676552 C19.1025173,404.676552 7.10542736e-15,385.574034 7.10542736e-15,362.009885 C7.10542736e-15,354.584736 1.93772021,347.288125 5.62162594,340.84129 L188.099293,21.5053731 C199.790385,1.04596203 225.853517,-6.06216498 246.312928,5.62892705 Z" id="Combined-Shape"></path>
          </g>
      </g>
    </svg>`
  }
}
