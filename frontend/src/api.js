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

// ── Geo/ASN lookup ─────────────────────────────────────────────────────────
// Routes through the backend /ip/{ip} proxy to avoid CORS restrictions.
// Direct browser-to-third-party geo lookups (ip-api.com, freeipapi.com, etc.)
// are blocked when the frontend runs on localhost or HTTPS origins.
export async function fetchIpInfo(ip) {
  // Primary: backend proxy — normalises the ip-api.com response server-side,
  // no CORS issues, works for both HTTP and HTTPS origins.
  try {
    const data = await request(`/ip/${encodeURIComponent(ip)}`)
    // ip-api.com returns status:'fail' for private/reserved ranges
    if (data.status === 'fail') throw new Error(data.message || 'ip-api.com fail')
    return data
  } catch (backendErr) {
    // Fallback: ipapi.co — CORS-enabled, HTTPS, free tier
    // Used only if the backend itself is unreachable.
    try {
      const r = await fetch(`https://ipapi.co/${encodeURIComponent(ip)}/json/`)
      if (!r.ok) throw new Error('ipapi.co ' + r.status)
      const d = await r.json()
      if (d.error) throw new Error(d.reason || 'ipapi.co error')
      // Normalise to ip-api.com shape so callers don't need to branch
      return {
        status:      'success',
        query:       d.ip,
        country:     d.country_name,
        countryCode: d.country_code,
        region:      d.region_code,
        regionName:  d.region,
        city:        d.city,
        zip:         d.postal,
        lat:         d.latitude,
        lon:         d.longitude,
        timezone:    d.timezone,
        isp:         d.org,
        org:         d.org,
        as:          d.asn,
        reverse:     d.hostname || '',
      }
    } catch (ipapiErr) {
      throw new Error(`Geo lookup failed — backend: ${backendErr.message} | ipapi.co: ${ipapiErr.message}`)
    }
  }
}

export async function fetchHttpInspect({ ip, port, scheme = 'http', path = '/' }) {
  return request('/http/inspect', {
    method: 'POST',
    body: JSON.stringify({ ip, port, scheme, path }),
  })
}

export async function fetchHttpScreenshot({ ip, port, scheme = 'http', path = '/', full_page = false }) {
  return request('/http/screenshot', {
    method: 'POST',
    body: JSON.stringify({ ip, port, scheme, path, full_page }),
  })
}

// ── TLS certificate info ───────────────────────────────────────────────────────
export async function fetchTlsCert(ip, port = 443) {
  return request(`/tls/${encodeURIComponent(ip)}/${port}`)
}
 
// ── robots.txt ────────────────────────────────────────────────────────────────
export async function fetchRobotsTxt({ ip, port = 80, scheme = 'http' }) {
  const params = new URLSearchParams({ ip, port, scheme })
  return request(`/recon/robots?${params}`)
}
 
// ── security.txt (RFC 9116) ───────────────────────────────────────────────────
export async function fetchSecurityTxt({ ip, port = 80, scheme = 'http' }) {
  const params = new URLSearchParams({ ip, port, scheme })
  return request(`/recon/security-txt?${params}`)
}
 
