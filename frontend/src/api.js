// frontend/src/api.js
import { getCachedRanges, saveCachedRanges } from './intel'

const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:8000'

async function request(path, init = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...init,
  })
  if (!res.ok) {
    const detail = await res.text()
    throw new Error(detail || res.statusText)
  }
  return res.json()
}

export async function fetchCountries() {
  return request('/countries')
}

export async function fetchRanges({ country, rirs, force, masscanHint }) {
  const selectedRirs = rirs || ['RIPE', 'ARIN', 'APNIC', 'LACNIC', 'AFRINIC']

  // ── Check Firestore range cache first (skip if force=true) ────────────
  if (!force) {
    try {
      const cached = await getCachedRanges(country, selectedRirs)
      if (cached) {
        console.log('[api] range cache hit:', country)
        return cached
      }
    } catch { /* fall through to live fetch */ }
  }

  // ── Live fetch from backend ────────────────────────────────────────────
  const params = new URLSearchParams()
  params.append('country', country)
  if (force) params.append('force', 'true')
  if (masscanHint) params.append('masscan_hint', 'true')
  selectedRirs.forEach((rir) => params.append('rir', rir))
  const data = await request(`/ranges?${params.toString()}`)

  // ── Save to Firestore in background ───────────────────────────────────
  saveCachedRanges(country, selectedRirs, data).catch(() => {})

  return { ...data, from_cache: false, age_days: 0, freshness: 'fresh' }
}

export async function fetchCves(software, version) {
  const params = new URLSearchParams({ software })
  if (version) params.append('version', version)
  return request(`/cves?${params.toString()}`)
}

export async function fetchPorts() {
  return request('/ports/probe')
}

export async function health() {
  return request('/health')
}

export async function startScan(payload) {
  return request('/scan', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
}

export async function getScanJob(jobId) {
  return request(`/scan/${jobId}`)
}

export function streamScanJob(jobId, onEvent, onDone, onError) {
  const url = `${API_BASE}/scan/${jobId}/stream`
  const es = new EventSource(url)
  es.onmessage = (e) => {
    try {
      const data = JSON.parse(e.data)
      onEvent(data)
      if (data.type === 'done') { es.close(); onDone?.() }
    } catch { /* ignore */ }
  }
  es.onerror = (e) => { es.close(); onError?.(e) }
  return es
}

// ── Country intel — Firestore directly, no backend roundtrip ─────────────
export async function fetchCountryIntel(country) {
  const { getCountryIntel } = await import('./intel')
  return getCountryIntel(country)
}

export async function contributeIntel(country, payload) {
  const { contributeCountryIntel } = await import('./intel')
  return contributeCountryIntel(country, payload)
}

// ── Geo/ASN lookup ────────────────────────────────────────────────────────
export async function fetchIpInfo(ip) {
  const sources = [
    async () => {
      const fields = 'status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query,reverse'
      const r = await fetch(`http://ip-api.com/json/${encodeURIComponent(ip)}?fields=${fields}`)
      if (!r.ok) throw new Error('ip-api.com ' + r.status)
      const d = await r.json()
      if (d.status === 'fail') throw new Error(d.message || 'ip-api.com fail')
      return d
    },
    async () => {
      const r = await fetch(`https://freeipapi.com/api/json/${encodeURIComponent(ip)}`)
      if (!r.ok) throw new Error('freeipapi ' + r.status)
      const d = await r.json()
      return {
        status: 'success', query: d.ipAddress,
        country: d.countryName, countryCode: d.countryCode,
        regionName: d.regionName, city: d.cityName,
        lat: d.latitude,  lon: d.longitude,
        isp: '', org: '', as: '', reverse: '',
      }
    },
  ]
  let lastErr
  for (const src of sources) {
    try { return await src() } catch (e) { lastErr = e }
  }
  throw new Error('All geo sources failed: ' + lastErr?.message)
}