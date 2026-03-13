// frontend/src/tlsQueue.js
// ─────────────────────────────────────────────────────────────────────────────
// Module-level throttled TLS fetch queue.
// At most CONCURRENCY fetches run simultaneously across the entire app.
// Results are cached so the same IP:port is only ever fetched once per session.
// ─────────────────────────────────────────────────────────────────────────────

import { fetchTlsCert } from './api'

const CONCURRENCY = 3          // max simultaneous /tls/ requests
const DELAY_MS    = 150        // ms gap between successive fetches

const cache    = {}            // key → result object
const pending  = {}            // key → Promise (in-flight dedup)
const queue    = []            // [{ key, ip, port, resolve, reject }]
let   running  = 0

function next() {
  if (running >= CONCURRENCY || queue.length === 0) return
  const { key, ip, port, resolve, reject } = queue.shift()
  running++

  fetchTlsCert(ip, port)
    .then(data => {
      cache[key] = data
      resolve(data)
    })
    .catch(err => {
      cache[key] = { error: err.message, sans: [], expired: false, self_signed: false }
      resolve(cache[key])   // resolve (not reject) so callers don't throw
    })
    .finally(() => {
      running--
      delete pending[key]
      setTimeout(next, DELAY_MS)
    })
}

/**
 * Enqueue a TLS fetch for ip:port.
 * Returns a Promise that resolves to the cert data (or an error object).
 * Concurrent calls for the same key share one in-flight Promise.
 */
export function enqueueTlsFetch(ip, port) {
  const key = `${ip}:${port}`

  // Already cached — return immediately
  if (cache[key]) return Promise.resolve(cache[key])

  // Already in-flight — share the same promise
  if (pending[key]) return pending[key]

  // Enqueue a new fetch
  const p = new Promise((resolve, reject) => {
    queue.push({ key, ip, port, resolve, reject })
  })
  pending[key] = p
  next()
  return p
}