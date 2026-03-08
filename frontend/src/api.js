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

export async function runScan(payload) {
  return request('/scan', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
}
