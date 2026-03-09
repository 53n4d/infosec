import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { TbAlertTriangle, TbCircle, TbDiamond } from 'react-icons/tb'
import { MdOutlineFiberManualRecord } from 'react-icons/md'
import { fetchCountryIntel } from '../api'

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

function freshnessColor(freshness) {
  if (freshness === 'fresh')  return 'var(--low)'
  if (freshness === 'recent') return 'var(--cyan)'
  if (freshness === 'aging')  return 'var(--med)'
  return 'var(--crit)'
}

function freshnessIcon(freshness) {
  return (
    <MdOutlineFiberManualRecord
      size={14}
      style={{ color: freshnessColor(freshness), flexShrink: 0 }}
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

// ─────────────────────────────────────────────────────────────────────────────
// Component
// ─────────────────────────────────────────────────────────────────────────────

export default function CountryIntel({ country, countryName, onUseData, onRunScan }) {
  const navigate = useNavigate()
  const [intel,    setIntel]    = useState(null)
  const [loading,  setLoading]  = useState(false)
  const [error,    setError]    = useState('')
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

  // ── Loading ──────────────────────────────────────────────────────────
  if (!country) return null

  if (loading) return (
    <div className="intel-card loading">
      <span className="pulse-dot" />
      Checking community intel for {country}…
    </div>
  )

  if (error) return null
  if (!intel) return null

  // ── No data yet ──────────────────────────────────────────────────────
  if (!intel.found) {
    return (
      <div className="intel-card no-data">
        <div className="intel-card-inner">
          <TbCircle size={18} style={{ color: 'var(--dim)', flexShrink: 0 }} />
          <div>
            <p className="intel-title">No community data for {country}</p>
            <p className="hint">Be the first to scan this country and contribute intel.</p>
          </div>
        </div>
      </div>
    )
  }

  const {
    stats       = {},
    top_software = [],
    cve_summary  = [],
    hits         = [],
    freshness,
    age_days,
    stale,
    scan_count,
  } = intel

  // ── Full card ────────────────────────────────────────────────────────
  return (
    <div className={`intel-card ${stale ? 'stale' : 'fresh'}`}>

      {/* ── Header ── */}
      <div className="intel-header">
        <div className="intel-header-left">
          <span className="intel-freshness-icon">
            {freshnessIcon(freshness)}
          </span>
          <div>
            <p className="intel-title">
              {countryName || country} community intel
            </p>
            <p className="hint" style={{ fontFamily: 'var(--mono-font)', fontSize: '0.72rem' }}>
              {age_days === 0 ? 'updated today' : `updated ${age_days}d ago`}
              {scan_count ? ` · ${scan_count} contributor${scan_count > 1 ? 's' : ''}` : ''}
              {stale && (
                <span style={{
                  color: 'var(--crit)',
                  marginLeft: 10,
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 4,
                }}>
                  <TbAlertTriangle size={12} aria-label="stale data" />
                  stale — recommend fresh scan
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
          <span className="hint" style={{ fontFamily: 'var(--mono-font)', fontSize: '0.65rem' }}>
            probed
          </span>
          <strong className="mono">{(stats.probed || 0).toLocaleString()}</strong>
        </div>
        <div className="intel-stat">
          <span className="hint" style={{ fontFamily: 'var(--mono-font)', fontSize: '0.65rem' }}>
            open hosts
          </span>
          <strong className="mono" style={{ color: 'var(--cyan)' }}>
            {(stats.open || 0).toLocaleString()}
          </strong>
        </div>
        <div className="intel-stat">
          <span className="hint" style={{ fontFamily: 'var(--mono-font)', fontSize: '0.65rem' }}>
            vuln hosts
          </span>
          <strong className="mono" style={{ color: 'var(--high)' }}>
            {(stats.vulns || 0).toLocaleString()}
          </strong>
        </div>
        <div className="intel-stat">
          <span className="hint" style={{ fontFamily: 'var(--mono-font)', fontSize: '0.65rem' }}>
            hits stored
          </span>
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
                <TbDiamond
                  size={9}
                  aria-hidden
                  style={{ color: 'var(--dim)', marginRight: 4, flexShrink: 0 }}
                />
                {sw}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* ── CVE summary ── */}
      {cve_summary.length > 0 && (
        <div className="intel-section">
          <p className="intel-section-label" style={{ display: 'flex', alignItems: 'center', gap: 0 }}>
            Top CVEs
            <button
              className="ghost small"
              style={{ marginLeft: 12, padding: '2px 8px', fontSize: '0.68rem' }}
              onClick={() => setExpanded((v) => !v)}
            >
              {expanded ? 'hide' : 'show all'}
            </button>
          </p>
          <div className="intel-cve-list">
            {(expanded ? cve_summary : cve_summary.slice(0, 3)).map((cve) => (
              <div key={cve.id} className="intel-cve-item">
                <span
                  className="badge strong"
                  style={{ fontFamily: 'var(--mono-font)', fontSize: '0.72rem', flexShrink: 0 }}
                >
                  {cve.id}
                </span>
                <span
                  className="mono"
                  style={{
                    color: severityColor(cve.score),
                    fontSize: '0.75rem',
                    fontWeight: 700,
                    flexShrink: 0,
                  }}
                >
                  {cve.score} {cve.severity}
                </span>
                <span style={{
                  color: 'var(--dim)',
                  fontSize: '0.75rem',
                  flex: 1,
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                  fontFamily: 'var(--mono-font)',
                }}>
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
                <span
                  style={{
                    width: 6,
                    height: 6,
                    borderRadius: '50%',
                    background: 'var(--low)',
                    flexShrink: 0,
                    display: 'inline-block',
                  }}
                  aria-hidden
                />
                <span
                  className="mono"
                  style={{ color: 'var(--cyan)', fontSize: '0.8rem', minWidth: 130 }}
                >
                  {hit.ip}
                </span>
                <span style={{ color: 'var(--dim)', fontSize: '0.78rem' }}>
                  :{hit.port}
                </span>
                {hit.software && (
                  <span className="version-tag" style={{ fontSize: '0.7rem', marginLeft: 8 }}>
                    {hit.software}
                  </span>
                )}
                {hit.cves?.length > 0 && (
                  <span
                    style={{
                      marginLeft: 'auto',
                      fontFamily: 'var(--mono-font)',
                      fontSize: '0.68rem',
                      color: 'var(--high)',
                      background: 'rgba(255,104,32,0.1)',
                      border: '1px solid rgba(255,104,32,0.25)',
                      padding: '1px 7px',
                      borderRadius: 2,
                      flexShrink: 0,
                    }}
                  >
                    {hit.cves.length} CVE{hit.cves.length > 1 ? 's' : ''}
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

    </div>
  )
}