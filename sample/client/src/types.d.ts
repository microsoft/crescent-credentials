/*
 *  Copyright (c) Microsoft Corporation.
 *  Licensed under the MIT license.
 */

/* eslint-disable no-unused-vars */

/*
  put global types here
  if you using build:watch, you may need to restart it after adding new types here or it may not recognize them
  TODO: add this to rollup watch files
*/

interface MESSAGE_PAYLOAD {
  action: string
  data: unknown
}

interface JWT { header: Record<string, unknown>, payload: Record<string, unknown>, signature: string }

type JWT_RECORDS = Array<{ url: string, jwt: JWT }>
