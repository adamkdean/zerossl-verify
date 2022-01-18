// Copyright 2022 Adam K Dean <adamkdean@googlemail.com>
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

import { ZeroSSL } from 'zerossl'
import dotenv from 'dotenv'
import express from 'express'

dotenv.config()

const port = process.env.HTTP_PORT || 8000
const accessKey = process.env.ZEROSSL_API_KEY || ''

const zerossl = new ZeroSSL({ accessKey })
const app = express()

app.get('/', async (req, res) => {
  const host = req.headers['x-forwarded-host'] as string || req.headers.host
  const keys = Object.keys(req.headers)
  const headers: string[] = []
  keys.forEach(key => headers.push(`${key}: ${req.headers[key]}`))
  return res.end(`<h1>${host}</h1><pre>${headers.join('\n')}</pre>`)
})

app.get('/.well-known/pki-validation/:value', async (req, res, next) => {
  // 1. Find a certificate for the current hostname
  const host = req.headers['x-forwarded-host'] as string || req.headers.host
  if (!host) return next()

  // 2. Get the certificate record
  const certs = await zerossl.listCertificates({ search: host, certificate_status: 'pending_validation', limit: 1 })
  if (certs.result_count === 0) return next()

  // 3. Make sure we can get the validation data
  const cert = certs.results[0]
  const validation = cert.validation.other_methods[host]
  if (!validation) return next()

  // 4. Ensure the path is correct
  const requiredPath = validation.file_validation_url_http.replace(`http://${host}`, '')
  if (req.path !== requiredPath) return next()

  // 5. Return the validation data
  const content = validation.file_validation_content.join('\n')
  return res.contentType('text/plain').send(content)
})

app.use((req, res) => {
  const host = req.headers['x-forwarded-host'] as string || req.headers.host
  console.log(`[${host}] ${req.url} not found`)
  return res.status(404).end(`[${host}] ${req.url} not found`)
})

app.listen(port, () => console.log(`Listening on port ${port}`))
