/*
 *  Copyright (c) Microsoft Corporation.
 *  Licensed under the MIT license.
 */

import { LitElement, html, css, type TemplateResult } from 'lit'
import { property } from 'lit/decorators.js'

export class ToggleSwitch extends LitElement {
  static styles = css`
    :host {
      display: block;
      --slider-height: 24px;
      --slider-width: 42px;
      --slider-ball-size: 20px;
      --font-size: 14px;
      font-family: inherit
    }

    .container {
      display: flex;
      justify-content: space-between;
      align-items: center;
      width: 100%;
    }

    .label {
      flex: 1;
      font-size: var(--font-size);
    }

    .switch {
      position: relative;
      display: inline-block;
      width: var(--slider-width);
      height: var(--slider-height);
    }

    .switch input {
      opacity: 0;
      width: 0;
      height: 0;
    }

    .slider {
      position: absolute;
      cursor: pointer;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background-color: #B0B0B0;
      transition: .4s;
      border-radius: calc(var(--slider-height) / 2);
    }

    .slider:before {
      position: absolute;
      content: "";
      height: var(--slider-ball-size);
      width: var(--slider-ball-size);
      left: 2px;
      bottom: 2px;
      background-color: white;
      transition: .4s;
      border-radius: 50%;
    }

    input:checked + .slider {
      background-color: #404040;
    }

    input:checked + .slider:before {
      transform: translateX(calc(var(--slider-width) - var(--slider-height)));
    }

  `

  @property({ type: Boolean, reflect: true }) checked = false
  @property({ type: String, reflect: true }) label = 'Toggle'

  render (): TemplateResult {
    return html`
      <div class="container">
        <span class="label">${this.label}</span>
        <label class="switch">
          <input type="checkbox" ?checked=${this.checked} @change=${this._onChange}>
          <span class="slider"></span>
        </label>
      </div>
    `
  }

  private readonly _onChange = (event: Event): void => {
    this.checked = (event.target as HTMLInputElement).checked
    this.dispatchEvent(new CustomEvent('change', { detail: { checked: this.checked } }))
  }
}

customElements.define('toggle-switch', ToggleSwitch)
