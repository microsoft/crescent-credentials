/*
 *  Copyright (c) Microsoft Corporation.
 *  Licensed under the MIT license.
 */

import 'dotenv/config'

const schemaList = process.env.SCHEMAS ?? 'jwt_corporate_1,mdl_1'

const config = {
  clientHelperUrl: process.env.CLIENT_HELPER_URL ?? 'http://127.0.0.1:8003',
  schemas: schemaList.replace(/\s/g, '').split(','),
  pollInterval: parseInt(process.env.PREPARE_POLL_INTERVAL ?? '5000'),
  cardColor: process.env.CARD_COLOR ?? '#4E95D9',
  autoOpen: (process.env.AUTO_OPEN ?? '').trim().toLowerCase() === 'true'
}

export function setClientHelperUrl (url: string): void {
  config.clientHelperUrl = url
}

export default config
