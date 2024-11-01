import 'dotenv/config'

const config = {
  client_helper_url: process.env.CLIENT_HELPER_URL ?? 'http://127.0.0.1:8003'
}

export function setClientHelperUrl (url: string): void {
  config.client_helper_url = url
}

export default config
