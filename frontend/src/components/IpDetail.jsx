import { useEffect, useMemo, useState } from 'react'
import { useParams, useLocation, Link } from 'react-router-dom'
import { fetchIpInfo } from '../api'

function severityColor(score) {
  const n = parseFloat(score)
  if (isNaN(n)) return 'var(--dim)'
  if (n >= 9.0) return 'var(--crit)'
  if (n >= 7.0) return 'var(--high)'
  if (n >= 4.0) return 'var(--med)'
  return 'var(--low)'
}

export default function IpDetail() {
  const { ip } = useParams()
  const location = useLocation()

  // Hit data: prefer router state, fall back to sessionStorage (new-tab case)
  const hitData = useMemo(() => {
    if (location.state?.hit) return location.state.hit
    for (let i = 0; i < sessionStorage.length; i++) {
      const key = sessionStorage.key(i)
      if (key?.startsWith(`hit_${ip}_`)) {
        try { return JSON.parse(sessionStorage.getItem(key)) } catch { /* ignore */ }
      }
    }
    return null
  }, [ip, location.state])

  const [geo, setGeo] = useState(null)
  const [geoError, setGeoError] = useState('')
  const [geoLoading, setGeoLoading] = useState(true)

  useEffect(() => {
    if (!ip) return
    setGeoLoading(true)
    setGeoError('')
    fetchIpInfo(ip)
      .then((data) => {
        if (data.status === 'fail') setGeoError(data.message || 'Lookup failed')
        else setGeo(data)
      })
      .catch((err) => setGeoError(err.message))
      .finally(() => setGeoLoading(false))
  }, [ip])

  return (
    <div className="ip-detail-page">
      <div className="ip-detail-card">

        {/* Header */}
        <div className="ip-detail-header">
          <Link to={-1} className="back-link">← Back</Link>
          <p className="mono eyebrow">IP Intelligence</p>
          <h1 className="ip-title">{ip}</h1>
          {hitData && (
            <div className="ip-hit-meta">
              <span className="status-dot open" style={{ display: 'inline-block', marginRight: 6 }} />
              <span className="mono" style={{ fontSize: '0.82rem', color: 'var(--accent)' }}>
                port {hitData.port} open
              </span>
              {hitData.software && (
                <span className="hit-software" style={{ marginLeft: 10 }}>{hitData.software}</span>
              )}
            </div>
          )}
        </div>

        {/* Geo section */}
        <div className="ip-section">
          <p className="ip-section-title mono">Geolocation / ASN</p>
          {geoLoading && <p className="hint">Resolving…</p>}
          {geoError && (
            <p className="error" style={{ marginTop: 8 }}>
              ⚠ {geoError}
            </p>
          )}
          {geo && (
            <div className="ip-detail-grid">
              {[
                ['Country',     `${geo.country} (${geo.countryCode})`],
                ['Region',      `${geo.regionName} (${geo.region})`],
                ['City',        `${geo.city}${geo.zip ? ' ' + geo.zip : ''}`],
                ['Coordinates', `${geo.lat}, ${geo.lon}`],
                ['Timezone',    geo.timezone],
                ['Reverse DNS', geo.reverse || '—'],
                ['ISP',         geo.isp],
                ['Org',         geo.org],
                ['AS',          geo.as],
              ].map(([label, value]) => (
                <div className="ip-field" key={label}>
                  <span className="ip-label mono">{label}</span>
                  <span className="ip-value">{value}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Banner section — only if we have hit data */}
        {hitData?.banner && (
          <div className="ip-section">
            <p className="ip-section-title mono">Banner — port {hitData.port}</p>
            <pre className="banner-pre">{hitData.banner}</pre>
          </div>
        )}

        {/* Version info */}
        {hitData?.version_info?.length > 0 && (
          <div className="ip-section">
            <p className="ip-section-title mono">Detected software</p>
            <div className="version-tags">
              {hitData.version_info.map((vi, i) => (
                <span key={i} className="version-tag">
                  <span className="mono">{vi.label}</span> {vi.value}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* CVEs */}
        {hitData?.cves?.length > 0 && (
          <div className="ip-section">
            <p className="ip-section-title mono">
              CVEs ({hitData.cves.length})
            </p>
            <div className="cve-detail-list">
              {hitData.cves.map((cve, i) => (
                <div key={i} className="cve-detail-item">
                  <div className="cve-detail-head">
                    <span className="badge strong">{cve.id}</span>
                    <span className="score-pill" style={{ color: severityColor(cve.score) }}>
                      CVSS {cve.score} — {cve.severity}
                    </span>
                  </div>
                  <p className="cve-desc">{cve.desc}</p>
                  <a
                    href={`https://nvd.nist.gov/vuln/detail/${cve.id}`}
                    target="_blank"
                    rel="noreferrer"
                    className="ip-detail-link"
                    style={{ fontSize: '0.75rem' }}
                  >
                    NVD →
                  </a>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* External pivots */}
        <div className="ip-section">
          <p className="ip-section-title mono">Pivot to</p>
          <div className="ip-actions">
            {[
              [`https://www.shodan.io/host/${ip}`,                    'Shodan'],
              [`https://www.virustotal.com/gui/ip-address/${ip}`,     'VirusTotal'],
              [`https://bgp.he.net/ip/${ip}`,                        'BGP.he.net'],
              [`https://viz.greynoise.io/ip/${ip}`,                  'GreyNoise'],
              [`https://www.abuseipdb.com/check/${ip}`,              'AbuseIPDB'],
              [`https://www.censys.io/hosts/${ip}`,                  'Censys'],
            ].map(([href, label]) => (
              <a key={label} href={href} target="_blank" rel="noreferrer" className="ghost small">
                {label} →
              </a>
            ))}
          </div>
        </div>

      </div>
    </div>
  )
}