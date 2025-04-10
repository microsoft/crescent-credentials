/*
 *  Copyright (c) Microsoft Corporation.
 *  Licensed under the MIT license.
 */

import { decode as decodeJwt } from './jwt.js'
import { decode as decodeMdoc, type mdocDocument } from './mdoc.js'

export interface Schema {
  decode: (encoded: string) => RESULT<JWT_TOKEN, Error> | RESULT<mdocDocument, Error>
  type: 'JWT' | 'MDOC'
  name: 'mdl_1' | 'jwt_corporate_1' | 'jwt_sd'
}

const schemas: Record<string, Schema> = {
  jwt_corporate_1: {
    decode: decodeJwt,
    type: 'JWT',
    name: 'jwt_corporate_1'
  },
  jwt_sd: {
    decode: decodeJwt,
    type: 'JWT',
    name: 'jwt_sd'
  },
  mdl_1: {
    decode: decodeMdoc,
    type: 'MDOC',
    name: 'mdl_1'
  }
}

export default schemas
