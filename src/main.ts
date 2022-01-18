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

app.use('*', (req, res, next) => {
  const datetime = new Date().toISOString()
  const host = req.headers['x-forwarded-host'] as string || req.headers.host
  console.log(`[${host}] ${datetime} ${req.method} ${req.url}`)
  next()
})

app.get('/', async (req, res) => {
  const host = req.headers['x-forwarded-host'] as string || req.headers.host
  const keys = Object.keys(req.headers)
  const headers: string[] = []
  keys.forEach(key => headers.push(`${key}: ${req.headers[key]}`))
  return res.end(`<h1>${host}</h1><pre>${headers.join('\n')}</pre>`)
})

app.get('/.well-known/pki-validation/:value', async (req, res, next) => {
  // Find a certificate for the current hostname
  const host = req.headers['x-forwarded-host'] as string || req.headers.host
  if (!host) {
    console.log('host is undefined')
    return next()
  }

  // Search certificate records for hostname
  const certs = await zerossl.listCertificates({ search: host, limit: 100 })
  if (certs.result_count === 0) {
    console.log(`no certificates found for hostname: ${host}`)
    return next()
  }

  // Find the correct certificate record
  let cert = null
  for (const result of certs.results) {
    console.log(`checking ${result.id} ${result.common_name}...`)

    if (result.status === 'cancelled') {
      console.log(`certificate ${result.id} ${result.common_name} has been cancelled`)
      continue
    }

    const validation = result.validation.other_methods[host]
    const requiredPath = validation.file_validation_url_http.replace(`http://${host}`, '')
    if (req.path === requiredPath) {
      console.log(`found certificate ${result.id} for hostname: ${host}`)
      console.log(`required path: ${requiredPath}`)
      cert = result
      break
    }

    console.log(`skipping certificate ${result.id} (${result.common_name}, ${result.status})`)
    console.log(`${req.path} !== ${requiredPath}`)
  }

  if (cert === null) {
    console.log(`no certificate found for hostname: ${host}`)
    return next()
  }

  // Return the validation data
  const content = cert.validation.other_methods[host].file_validation_content.join('\n')
  console.log(`returning validation data for certificate ${cert.id}`)
  return res.contentType('text/plain').send(content)
})

app.use((req, res) => {
  const host = req.headers['x-forwarded-host'] as string || req.headers.host
  console.log(`[${host}] ${req.url} not found`)
  return res.status(404).end(`[${host}] ${req.url} not found`)
})

app.listen(port, () => console.log(`Listening on port ${port}`))
