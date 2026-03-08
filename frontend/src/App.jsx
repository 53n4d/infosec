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
  const params = new URLSearchParams()
  params.append('country', country)
  if (force) params.append('force', 'true')
  if (masscanHint) params.append('masscan_hint', 'true')
  rirs?.forEach((rir) => params.append('rir', rir))
  return request(`/ranges?${params.toString()}`)
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

// Geo/ASN lookup — proxied through FastAPI backend to avoid ip-api.com CORS issues
export async function fetchIpInfo(ip) {
  // Call geo APIs directly from the browser — they support CORS.
  // Try multiple free sources in order.
  const sources = [
    // ipapi.co — CORS-enabled, no key needed, 1k/day free
    async () => {
      const r = await fetch(`https://ipapi.co/${encodeURIComponent(ip)}/json/`, {
        headers: { 'Accept': 'application/json' }
      })
      if (!r.ok) throw new Error(`ipapi.co ${r.status}`)
      const d = await r.json()
      if (d.error) throw new Error(d.reason || d.error)
      return {
        status: 'success', query: d.ip,
        country: d.country_name, countryCode: d.country_code,
        regionName: d.region, city: d.city, zip: d.postal,
        lat: d.latitude, lon: d.longitude,
        timezone: d.timezone, isp: d.org, org: d.org, as: d.asn,
        reverse: d.hostname || '',
      }
    },
    // ip-api.com — CORS-enabled on HTTP only (browser fetch allows mixed in some contexts)
    // Used as fallback
    async () => {
      const fields = 'status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query,reverse'
      const r = await fetch(`http://ip-api.com/json/${encodeURIComponent(ip)}?fields=${fields}`)
      if (!r.ok) throw new Error(`ip-api.com ${r.status}`)
      const d = await r.json()
      if (d.status === 'fail') throw new Error(d.message || 'ip-api.com fail')
      return d
    },
  ]

  let lastErr
  for (const src of sources) {
    try { return await src() } catch (e) { lastErr = e }
  }
  throw new Error(`All geo sources failed: ${lastErr?.message}`)
}