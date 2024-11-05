/*
 *  Copyright (c) Microsoft Corporation.
 *  Licensed under the MIT license.
 */

/**
 * `ByteReader` is a class for reading byte-aligned data from a buffer while automatically advancing the reading position.
 * Peeking is also supported, allowing for reading without advancing the position.
 * @class ByteReader
 */
export class ByteReader {
  /**
     * The DataView used for reading data from the buffer.
     * @private
     */
  readonly #view: DataView

  /**
     * The current position within the buffer.
     * @private
     */
  #index: number

  /**
     * The end position of the buffer, indicating the total length.
     * @private
     */
  readonly #end: number

  /**
     * Flag to control whether the reading index should advance after a read operation.
     * @private
     */
  #noAdvance: boolean

  /**
     * Initializes a new instance of the ByteReader class with a given Uint8Array buffer.
     * @param buffer The Uint8Array buffer to be read.
     */
  constructor (buffer: Uint8Array) {
    /*
      TODO: Read from a stream instead of a buffer so we don't have to download an entire file into memory.
    */
    this.#view = new DataView(buffer.buffer, buffer.byteOffset)
    this.#index = 0
    this.#end = buffer.length
    this.#noAdvance = false
  }

  private littleEndian = true

  get endianness (): 'big' | 'little' {
    return this.littleEndian ? 'little' : 'big'
  }

  set endianness (value: 'big' | 'little') {
    this.littleEndian = value === 'little'
  }

  /**
     * Reads a single byte from the buffer.
     * @returns {number} The next byte in the buffer.
     */
  byte = (): number => {
    return this.#view.getUint8(this.advance(1))
  }

  /**
     * Reads a 16-bit unsigned integer from the buffer.
     * @returns {number} The next 16-bit unsigned integer in the buffer.
     */
  uint16 = (littleEndian?: boolean | undefined): number => {
    return this.#view.getUint16(this.advance(2), littleEndian)
  }

  /**
     * Reads a 24-bit unsigned integer from the buffer.
     * @returns {number} The next 24-bit unsigned integer in the buffer.
     */
  uint24 = (littleEndian?: boolean | undefined): number => {
    const uint8 = this.#view.getUint8(this.advance(1))
    const uint16 = this.#view.getUint16(this.advance(2), littleEndian)
    return (uint8 << 16) + uint16
  }

  /**
     * Reads a 32-bit unsigned integer from the buffer.
     * @returns {number} The next 32-bit unsigned integer in the buffer.
     */
  uint32 = (littleEndian?: boolean | undefined): number => {
    return this.#view.getUint32(this.advance(4), littleEndian)
  }

  /**
   * Reads a 64-bit unsigned integer from the buffer.
   * Throws error if the number exceeds MAX_SAFE_INTEGER.
   * @returns {number} The next 64-bit unsigned integer in the buffer.
   */
  uint64 = (littleEndian?: boolean | undefined): number => {
    const peeking = this.#noAdvance
    const uint64 = (this.uint32(littleEndian) * 0x100000000) + (peeking ? this.peek.uint32(littleEndian) : this.uint32(littleEndian))
    if (uint64 > Number.MAX_SAFE_INTEGER) {
      throw new RangeError('Number exceeds MAX_SAFE_INTEGER')
    }
    return uint64
  }

  /**
     * Creates and returns a new Uint8Array view of the specified length from the current position of the buffer.
     * If no length is provided, it defaults to the remaining length of the buffer.
     *
     * @param {number} [length] - The length of the new Uint8Array. If not provided, the length will be set to
     *                            the remaining bytes in the buffer from the current position.
     * @returns {Uint8Array} A new Uint8Array view of the buffer starting from the current position with the specified length.
     */
  Uint8Array = (length = this.remaining): Uint8Array => {
    if (length > this.remaining) {
      throw new RangeError('Buffer too small')
    }
    return new Uint8Array(this.#view.buffer, this.#view.byteOffset + this.advance(length), length)
  }

  /**
     * Moves the current reading position by a specified offset.
     * @param offset The offset by which to move the reading position.
     * @returns {ByteReader} This ByteReader instance for chaining.
     */
  move = (offset: number): this => {
    this.test(offset)
    this.#index += offset
    return this
  }

  /**
     * Moves the current reading to the absolute specified offset from the beginning of the buffer.
     * @param offset The offset by which to move the reading position.
     * @returns {ByteReader} This ByteReader instance for chaining.
     */
  absolute = (offset: number): this => {
    this.test(offset)
    this.#index = offset
    return this
  }

  /**
     * Gets the current offset within the buffer.
     * @returns {number} The current reading position in the buffer.
     */
  get offset (): number {
    return this.#index
  }

  /**
     * Gets the length, in bytes, of the entire buffer.
     * @returns {number} The length, in bytes, of the entire buffer.
     */
  get length (): number {
    return this.#end
  }

  /**
     * Determines if the end of the buffer has been reached.
     * @returns {boolean} True if the reading position has reached or surpassed the buffer length; otherwise, false.
     */
  get finished (): boolean {
    return this.#index >= this.#end
  }

  /**
     * Checks if the specified offset goes beyond the buffer bounds.
     * @param offset The offset to test.
     * @private
     * @throws {RangeError} Throws an error if the operation would exceed the buffer boundaries.
     */
  private test (offset: number): void {
    if (this.#index + offset > this.#end || this.#index + offset < 0) {
      throw new RangeError('Buffer too small')
    }
  }

  /**
     * Advances the current reading position by a specified offset, unless noAdvance is set.
     * @param offset The offset by which to potentially advance the reading position.
     * @private
     * @returns {number} The reading position before any potential advancement.
     */
  private advance (offset: number): number {
    this.test(offset)
    const index = this.#index
    this.#index += (this.#noAdvance ? 0 : offset)
    this.#noAdvance = false
    return index
  }

  /**
     * Enables peek mode, where the next read operation does not advance the reading position.
     * @returns {ByteReader} This ByteReader instance for chaining.
     */
  get peek (): this {
    this.#noAdvance = true
    return this
  }

  /**
     * Reads a string from the current position in the buffer. If a length is specified, it reads that many bytes as a string.
     * If length is unspecified, it reads until the end of the buffer.
     * If the length is 0, it reads until a null terminator is reached. If no null terminator is found, a RangeError is thrown.
     *
     * @param {number} [length] - The number of bytes to read as a string. If omitted, reads until the end of the buffer. If zero, reads until a null terminator.
     * @returns {string} The decoded string from the buffer.
    */
  string (length?: number): string {
    const nullTerminated = length === 0
    const peek = this.#noAdvance
    if (length == null) {
      length = this.remaining
    }
    if (nullTerminated) {
      length = this.findNext(0)
      if (length === -1) {
        throw new RangeError('Null terminator not found')
      }
    }
    const decoder = new TextDecoder('utf-8')
    const str = decoder.decode(this.Uint8Array(length))
    if (nullTerminated && !peek) { // move past the null terminator (when not peeking)
      this.move(1)
    }
    return str
  }

  /**
     * Gets the remaining byte count of the buffer.
     * @returns {number} The remaining bytes in the buffer.
    */
  get remaining (): number {
    return this.#end - this.#index
  }

  /**
     * Searches the buffer from the current position for the next occurrence of the specified byte value
     * and returns the offset from the current position to the location of the byte. If the byte is not found,
     * it returns -1.
     *
     * @param {number} byte - The byte value to search for in the buffer.
     * @returns {number} The offset from the current position to the found byte, or -1 if the byte is not found.
     */
  findNext (byte: number): number {
    let i = this.#index
    while (i < this.#end) {
      const b = this.#view.getUint8(i)
      if (b === byte) {
        return i - this.#index
      }
      i++
    }
    return -1
  }
}
