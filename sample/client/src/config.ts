import 'dotenv/config'

const schemaList = process.env.SCHEMAS ?? 'jwt_corporate_1,mdl_1'

const config = {
  client_helper_url: process.env.CLIENT_HELPER_URL ?? 'http://127.0.0.1:8003',
  schemas: schemaList.replace(/\s/g, '').split(',')
}

export function setClientHelperUrl (url: string): void {
  config.client_helper_url = url
}

export default config
