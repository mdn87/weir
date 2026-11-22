import { readFileSync } from 'node:fs'
import { createServer } from 'node:http'

const [pagePath, socketPath] = process.argv.slice(2)
const page = readFileSync(pagePath)
const server = createServer({ maxHeaderSize: 8192, headersTimeout: 5000, requestTimeout: 5000 }, (request, response) => {
  if (request.url !== '/') {
    response.writeHead(404, { 'content-length': '0' }).end()
    return
  }
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    response.writeHead(405, { allow: 'GET, HEAD', 'content-length': '0' }).end()
    return
  }
  response.writeHead(200, {
    connection: 'close',
    'content-type': 'text/html; charset=utf-8',
    'content-security-policy': "default-src 'none'; base-uri 'none'; form-action 'none'",
    'cache-control': 'no-store',
    'content-length': page.length,
  })
  response.end(request.method === 'HEAD' ? undefined : page)
})
server.maxConnections = 32
server.listen(socketPath)
