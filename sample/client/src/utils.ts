/*
 *  Copyright (c) Microsoft Corporation.
 *  Licensed under the MIT license.
 */

/**
 * Get an element by its id. The element is expected to exist.
 * Throws an error if the element is not found.
 * @param id {string} Id of the element to get
 * @returns {HTMLElement} The element with the given id
 */
export function getElementById (id: string): HTMLElement {
  const element = document.getElementById(id)
  if (element == null) {
    throw new Error(`Element with id ${id} not found`)
  }
  return element
}
