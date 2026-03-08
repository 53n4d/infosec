import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { FaCircle, FaRegCircle } from 'react-icons/fa'
import { FiAlertTriangle } from 'react-icons/fi'
import { GoDiamond } from 'react-icons/go'
import { fetchCountryIntel } from '../api'

function freshnessColor(freshness) {
  if (freshness === 'fresh')  return 'var(--accent)'
  if (freshness === 'recent') return 'var(--low)'
  if (freshness === 'aging')  return 'var(--med)'
  return 'var(--crit)'
}

function freshnessIcon(freshness) {
  return (
    <FaCircle
      style={{ color: freshnessColor(freshness) }}
      size={14}
      aria-label={`${freshness} freshness`}
    />
  )
}

function severityColor(score) {
  const n = parseFloat(score)
  if (isNaN(n)) return 'var(--dim)'
  if (n >= 9.0) return 'var(--crit)'
  if (n >= 7.0) return 'var(--high)'
  if (n >= 4.0) return 'var(--med)'
  return 'var(--low)'
}

export default function CountryIntel({ country, countryName, onUseData, onRunScan }) {
  const navigate = useNavigate()
  const [intel, setIntel] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [expanded, setExpanded] = useState(false)

  useEffect(() => {
    if (!country) return
    setIntel(null)
    setError('')
    setLoading(true)
    fetchCountryIntel(country)
      .then((data) => setIntel(data))
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false))
  }, [country])

  if (!country) return null
  if (loading) return (
    <div className="intel-card loading">
      <span className="pulse-dot" />
      <span style={{ marginLeft: 10, color: 'var(--dim)', fontSize: '0.85rem' }}>
        Checking community intel for {country}…
      </span>
    </div>
  )
  if (error) return null
  if (!intel) return null

  // No community data yet
  if (!intel.found) {
    return (
      <div className="intel-card no-data">
        <div className="intel-card-inner">
          <FaRegCircle style={{ fontSize: '1.1rem', color: 'var(--dim)' }} />
          <div>
            <p className="intel-title">No community data for {country}</p>
            <p className="hint">Be the first to scan this country and contribute intel.</p>
          </div>
        </div>
      </div>
    )
  }

  const { stats = {}, top_software = [], cve_summary = [], hits = [], freshness, age_days, stale, scan_count } = intel

  return (
    <div className={`intel-card ${stale ? 'stale' : 'fresh'}`}>
      {/* ── Header ── */}
      <div className="intel-header">
        <div className="intel-header-left">
          <span className="intel-freshness-icon">{freshnessIcon(freshness)}</span>
          <div>
            <p className="intel-title">
              {countryName || country} community intel
            </p>
            <p className="hint mono" style={{ fontSize: '0.75rem' }}>
              {age_days === 0 ? 'updated today' : `updated ${age_days}d ago`}
              {scan_count ? ` · ${scan_count} contributor${scan_count > 1 ? 's' : ''}` : ''}
              {stale && (
                <span style={{ color: 'var(--crit)', marginLeft: 8, display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                  <FiAlertTriangle aria-label="stale data" /> stale — recommend fresh scan
                </span>
              )}
            </p>
          </div>
        </div>
        <div className="intel-actions">
          <button className="primary small" onClick={() => onUseData(intel)}>
            Use this data
          </button>
          <button className="ghost small" onClick={() => onRunScan(intel)}>
            Run fresh scan
          </button>
        </div>
      </div>

      {/* ── Stats row ── */}
      <div className="intel-stats">
        <div className="intel-stat">
          <span className="mono" style={{ color: 'var(--dim)', fontSize: '0.72rem' }}>probed</span>
          <strong className="mono">{(stats.probed || 0).toLocaleString()}</strong>
        </div>
        <div className="intel-stat">
          <span className="mono" style={{ color: 'var(--dim)', fontSize: '0.72rem' }}>open hosts</span>
          <strong className="mono" style={{ color: 'var(--accent)' }}>{(stats.open || 0).toLocaleString()}</strong>
        </div>
        <div className="intel-stat">
          <span className="mono" style={{ color: 'var(--dim)', fontSize: '0.72rem' }}>vuln hosts</span>
          <strong className="mono" style={{ color: 'var(--high)' }}>{(stats.vulns || 0).toLocaleString()}</strong>
        </div>
        <div className="intel-stat">
          <span className="mono" style={{ color: 'var(--dim)', fontSize: '0.72rem' }}>hits stored</span>
          <strong className="mono">{hits.length}</strong>
        </div>
      </div>

      {/* ── Top software ── */}
      {top_software.length > 0 && (
        <div className="intel-section">
          <p className="intel-section-label">Top software</p>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {top_software.map((sw) => (
              <span key={sw} className="version-tag">
                <span className="mono" style={{ color: 'var(--dim)', fontSize: '0.7rem', marginRight: 4 }}>
                  <GoDiamond aria-hidden />
                </span>
                {sw}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* ── CVE summary ── */}
      {cve_summary.length > 0 && (
        <div className="intel-section">
          <p className="intel-section-label">
            Top CVEs
            <button
              className="ghost small"
              style={{ marginLeft: 12, padding: '2px 8px', fontSize: '0.7rem' }}
              onClick={() => setExpanded((v) => !v)}
            >
              {expanded ? 'hide' : 'show all'}
            </button>
          </p>
          <div className="intel-cve-list">
            {(expanded ? cve_summary : cve_summary.slice(0, 3)).map((cve) => (
              <div key={cve.id} className="intel-cve-item">
                <span className="badge strong mono" style={{ fontSize: '0.75rem' }}>{cve.id}</span>
                <span
                  className="mono"
                  style={{ color: severityColor(cve.score), fontSize: '0.78rem', fontWeight: 700 }}
                >
                  {cve.score} {cve.severity}
                </span>
                <span style={{ color: 'var(--dim)', fontSize: '0.78rem', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {cve.desc}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Recent hits preview ── */}
      {hits.length > 0 && (
        <div className="intel-section">
          <p className="intel-section-label">Recent hits (preview)</p>
          <div className="intel-hits-preview">
            {hits.slice(-8).reverse().map((hit, i) => (
              <div
                key={i}
                className="intel-hit-row"
                onClick={() => navigate('/ip/' + encodeURIComponent(hit.ip), { state: { hit } })}
              >
                <span className="status-dot open" />
                <span className="mono" style={{ color: 'var(--accent)', fontSize: '0.82rem', minWidth: 130 }}>{hit.ip}</span>
                <span style={{ color: 'var(--dim)', fontSize: '0.8rem' }}>:{hit.port}</span>
                {hit.software && (
                  <span className="version-tag" style={{ fontSize: '0.72rem', marginLeft: 8 }}>{hit.software}</span>
                )}
                {hit.cves?.length > 0 && (
                  <span className="cve-badge" style={{ marginLeft: 'auto' }}>{hit.cves.length} CVE{hit.cves.length > 1 ? 's' : ''}</span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
