import { useState, useEffect, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { fetchCountries } from '../api'
import CountryIntel from './CountryIntel'

function timeAgo(ts) {
  if (!ts) return '—'
  const diff = Date.now() - ts
  const mins  = Math.floor(diff / 60000)
  const hours = Math.floor(diff / 3600000)
  const days  = Math.floor(diff / 86400000)
  if (mins  <  1) return 'just now'
  if (mins  < 60) return `${mins}m ago`
  if (hours < 24) return `${hours}h ago`
  return `${days}d ago`
}

function statusColor(status) {
  if (status === 'running') return 'var(--accent)'
  if (status === 'done')    return 'var(--low)'
  if (status === 'error')   return 'var(--crit)'
  if (status === 'stopped') return 'var(--dim)'
  return 'var(--dim)'
}

export default function ScanDashboard() {
  const navigate = useNavigate()

  // ── Local scan history from localStorage ──────────────────────────────
  const [scans, setScans] = useState([])

  // ── Country intel lookup ───────────────────────────────────────────────
  const [countries, setCountries]           = useState([])
  const [countryInput, setCountryInput]     = useState('')
  const [country, setCountry]               = useState('')
  const [pickerOpen, setPickerOpen]         = useState(false)
  const [intelVisible, setIntelVisible]     = useState(false)
  const [intelCountry, setIntelCountry]     = useState('')
  const [intelCountryName, setIntelCountryName] = useState('')

  useEffect(() => {
    // Load local scans from localStorage
    const found = []
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i)
      if (key && key.startsWith('scan_')) {
        try {
          const s = JSON.parse(localStorage.getItem(key))
          if (s && s.jobId) found.push(s)
        } catch { /* ignore */ }
      }
    }
    found.sort((a, b) => (b.startedAt || 0) - (a.startedAt || 0))
    setScans(found)

    // Load countries for intel picker
    fetchCountries()
      .then((data) => {
        setCountries(data)
        if (data.length) {
          setCountry(data[0].code)
          setCountryInput(`${data[0].code} - ${data[0].name}`)
          setIntelCountryName(data[0].name)
        }
      })
      .catch(() => {})
  }, [])

  const filteredCountries = useMemo(() => {
    const term = countryInput.toLowerCase()
    if (!term.trim()) return countries
    return countries.filter(
      (c) => c.code.toLowerCase().includes(term) || c.name.toLowerCase().includes(term)
    )
  }, [countries, countryInput])

  const commitCountry = (code) => {
    const found = countries.find((c) => c.code === code)
    setCountry(code)
    setCountryInput(found ? `${found.code} - ${found.name}` : code)
    setIntelCountryName(found?.name || code)
    setPickerOpen(false)
    setIntelVisible(false)
  }

  const handleDeleteScan = (e, jobId) => {
    e.stopPropagation()
    localStorage.removeItem('scan_' + jobId)
    // Also clean up any hit keys for this scan
    const toRemove = []
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i)
      if (k && k.startsWith('hit_' + jobId + '_')) toRemove.push(k)
    }
    toRemove.forEach((k) => localStorage.removeItem(k))
    setScans((prev) => prev.filter((s) => s.jobId !== jobId))
  }

  // ── Intel handlers ─────────────────────────────────────────────────────
  const handleGetIntel = () => {
    if (!country) return
    setIntelCountry(country)
    setIntelVisible(true)
  }

  // "Use this data" — pre-populate scan console with intel hits
  const handleUseData = (intel) => {
    const rangesText = (intel.ranges || []).join('\n')
    navigate('/scan/new', { state: { ranges: rangesText, intelHits: intel.hits || [], intelCountry: intel.country } })
  }

  // "Run fresh scan" — go to new scan with ranges pre-filled
  const handleRunScan = (intel) => {
    const rangesText = (intel.ranges || []).join('\n')
    navigate('/scan/new', { state: { ranges: rangesText, autoStart: true } })
  }

  return (
    <div className="scan-dashboard">
      {/* ── Country intel lookup panel ─────────────────────────────────── */}
      <div className="intel-lookup-panel">
        <div className="intel-lookup-header">
          <div>
            <h2 style={{ fontSize: '1.4rem', color: '#fff', marginBottom: 4 }}>
              Country Intelligence
            </h2>
            <p className="hint">
              Check community scan data before running your own scan.
            </p>
          </div>
        </div>

        <div className="intel-lookup-form">
          <div className="combo" style={{ flex: 1, position: 'relative' }}>
            <input
              value={countryInput}
              onChange={(e) => { setCountryInput(e.target.value); setPickerOpen(true) }}
              onFocus={() => setPickerOpen(true)}
              onBlur={() => setTimeout(() => setPickerOpen(false), 120)}
              placeholder="Search country…"
              className="intel-country-input"
            />
            {pickerOpen && filteredCountries.length > 0 && (
              <div className="combo-list">
                {filteredCountries.slice(0, 20).map((c) => (
                  <button
                    key={c.code}
                    className="combo-item"
                    onMouseDown={(e) => e.preventDefault()}
                    onClick={() => commitCountry(c.code)}
                  >
                    <span className="mono">{c.code}</span>
                    <span>{c.name}</span>
                  </button>
                ))}
              </div>
            )}
          </div>
          <button className="primary" onClick={handleGetIntel} disabled={!country}>
            Get Intel
          </button>
          <button
            className="ghost"
            onClick={() => navigate('/scan/new', { state: { autoStart: false } })}
          >
            + New Scan
          </button>
        </div>

        {/* CountryIntel result card */}
        {intelVisible && intelCountry && (
          <CountryIntel
            country={intelCountry}
            countryName={intelCountryName}
            onUseData={handleUseData}
            onRunScan={handleRunScan}
          />
        )}
      </div>

      {/* ── Local scan history ─────────────────────────────────────────── */}
      <div className="scan-history-section">
        <div className="scan-dashboard-header">
          <h2>Your Scans</h2>
          {scans.length > 0 && (
            <span className="hint mono">{scans.length} scan{scans.length > 1 ? 's' : ''} stored locally</span>
          )}
        </div>

        {scans.length === 0 ? (
          <div className="scan-dashboard-empty">
            <p style={{ color: 'var(--dim)', marginBottom: 12 }}>No local scans yet.</p>
            <button className="primary" onClick={() => navigate('/scan/new')}>
              + Start a scan
            </button>
          </div>
        ) : (
          <div className="scan-card-list">
            {scans.map((scan) => (
              <div
                key={scan.jobId}
                className="scan-card"
                onClick={() => navigate('/scan/' + scan.jobId)}
              >
                <div className="scan-card-top">
                  <div>
                    <p className="mono" style={{ fontSize: '0.72rem', color: 'var(--dim)', marginBottom: 4 }}>
                      {scan.startedAt ? new Date(scan.startedAt).toLocaleString() : '—'}
                      <span style={{ marginLeft: 8 }}>{timeAgo(scan.startedAt)}</span>
                    </p>
                    <p className="scan-card-ranges mono">
                      {(scan.ranges || []).slice(0, 2).join(', ')}
                      {(scan.ranges || []).length > 2 && (
                        <span style={{ color: 'var(--dim)' }}> +{scan.ranges.length - 2} more</span>
                      )}
                    </p>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 6 }}>
                    <span
                      className="mono"
                      style={{
                        fontSize: '0.72rem',
                        color: statusColor(scan.status),
                        border: `1px solid ${statusColor(scan.status)}`,
                        padding: '2px 8px',
                        borderRadius: 2,
                        textTransform: 'uppercase',
                        letterSpacing: '0.08em',
                      }}
                    >
                      {scan.status || 'unknown'}
                    </span>
                    <button
                      className="ghost small"
                      style={{ fontSize: '0.7rem', padding: '2px 8px', color: 'var(--crit)', borderColor: 'var(--crit)' }}
                      onClick={(e) => handleDeleteScan(e, scan.jobId)}
                    >
                      delete
                    </button>
                  </div>
                </div>
                <div className="scan-card-stats">
                  <span>
                    <span style={{ color: 'var(--dim)' }}>probed </span>
                    <strong className="mono">{(scan.probed || 0).toLocaleString()}</strong>
                  </span>
                  <span>
                    <span style={{ color: 'var(--dim)' }}>open </span>
                    <strong className="mono" style={{ color: 'var(--accent)' }}>{(scan.open || 0).toLocaleString()}</strong>
                  </span>
                  <span>
                    <span style={{ color: 'var(--dim)' }}>vulns </span>
                    <strong className="mono" style={{ color: 'var(--high)' }}>{(scan.vulns || 0).toLocaleString()}</strong>
                  </span>
                </div>
                <p className="mono hint" style={{ marginTop: 8, fontSize: '0.7rem', color: 'var(--border2)' }}>
                  {scan.jobId}
                </p>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}