import { useEffect, useState } from 'react'
import { useParams, useLocation, useNavigate } from 'react-router-dom'
import { FiAlertTriangle, FiArrowUpRight, FiCamera } from 'react-icons/fi'
import { fetchIpInfo, fetchHttpScreenshot } from '../api'

function severityColor(score) {
  const n = parseFloat(score)
  if (isNaN(n)) return 'var(--dim)'
  if (n >= 9.0) return 'var(--crit)'
  if (n >= 7.0) return 'var(--high)'
  if (n >= 4.0) return 'var(--med)'
  return 'var(--low)'
}

function pivotLinks(ip) {
  return [
    { href: 'https://www.shodan.io/host/' + ip,                label: 'Shodan' },
    { href: 'https://www.virustotal.com/gui/ip-address/' + ip, label: 'VirusTotal' },
    { href: 'https://bgp.he.net/ip/' + ip,                    label: 'BGP.he.net' },
    { href: 'https://viz.greynoise.io/ip/' + ip,              label: 'GreyNoise' },
    { href: 'https://www.abuseipdb.com/check/' + ip,          label: 'AbuseIPDB' },
    { href: 'https://www.censys.io/hosts/' + ip,              label: 'Censys' },
  ]
}

export default function IpDetail() {
  const { ip } = useParams()
  const location = useLocation()
  const navigate = useNavigate()

  const [hitData, setHitData] = useState(location.state?.hit || null)

  useEffect(() => {
    if (hitData) return
    let attempts = 0
    const poll = setInterval(() => {
        console.log('polling... ip param is:', ip)
        console.log('localStorage keys:', Object.keys(localStorage))
        for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i)
        console.log('checking key:', key, '| starts with:', 'hit_' + ip + '_')
        if (key && key.startsWith('hit_' + ip + '_')) {
            try {
            const parsed = JSON.parse(localStorage.getItem(key))
            if (parsed) {
                setHitData(parsed)
                clearInterval(poll)
                return
            }
            } catch { /* ignore */ }
        }
        }
        attempts++
        if (attempts >= 10) clearInterval(poll)
    }, 50)
    return () => clearInterval(poll)
  }, [ip, hitData])

  const [geo, setGeo] = useState(null)
  const [geoError, setGeoError] = useState('')
  const [geoLoading, setGeoLoading] = useState(true)
  const [shot, setShot] = useState(null)
  const [shotLoading, setShotLoading] = useState(false)
  const [shotError, setShotError] = useState('')
  const [shotModalOpen, setShotModalOpen] = useState(false)

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

  const canScreenshot = hitData && [80, 443].includes(hitData.port)

  const grabScreenshot = async () => {
    if (!canScreenshot) return
    setShotLoading(true)
    setShotError('')
    try {
      const scheme = hitData.port === 443 ? 'https' : 'http'
      const data = await fetchHttpScreenshot({ ip, port: hitData.port, scheme, full_page: false })
      if (data.error) throw new Error(data.error)
      setShot({ ...data, scheme })
    } catch (e) {
      setShotError(e.message)
      setShot(null)
    } finally {
      setShotLoading(false)
    }
  }

  const geoRows = geo ? [
    ['Country',     geo.country + ' (' + geo.countryCode + ')'],
    ['Region',      geo.regionName + ' (' + geo.region + ')'],
    ['City',        geo.zip ? geo.city + ' ' + geo.zip : geo.city],
    ['Coordinates', geo.lat + ', ' + geo.lon],
    ['Timezone',    geo.timezone],
    ['Reverse DNS', geo.reverse || '—'],
    ['ISP',         geo.isp],
    ['Org',         geo.org],
    ['AS',          geo.as],
  ] : []

  return (
    <div className="ip-detail-page">
      <div className="ip-detail-card">

        <div className="ip-detail-header">
          <button className="back-link" onClick={() => {
            if (window.history.length > 1) {
              navigate(-1)
            } else {
              navigate('/scan')
            }
          }}>
            &larr; Back
          </button>
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

        <div className="ip-section">
          <p className="ip-section-title mono">Geolocation / ASN</p>
          {geoLoading && <p className="hint">Resolving…</p>}
          {geoError && (
            <p className="error" style={{ marginTop: 8, display: 'inline-flex', alignItems: 'center', gap: 6 }}>
              <FiAlertTriangle aria-label="warning" /> {geoError}
            </p>
          )}
          {geo && (
            <div className="ip-detail-grid">
              {geoRows.map(([label, value]) => (
                <div className="ip-field" key={label}>
                  <span className="ip-label mono">{label}</span>
                  <span className="ip-value">{value}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {hitData && hitData.banner && (
          <div className="ip-section">
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
              <p className="ip-section-title mono" style={{ marginBottom: 0 }}>
                Banner — port {hitData.port}
              </p>
              {canScreenshot && (
                <button
                  type="button"
                  className="ghost small"
                  onClick={grabScreenshot}
                  disabled={shotLoading}
                  style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}
                >
                  <FiCamera size={12} />
                  {shotLoading ? 'Capturing…' : 'Screenshot'}
                </button>
              )}
              {shot && shot.title && (
                <span className="hint" style={{ color: 'var(--accent)' }}>
                  {shot.title} {shot.status ? `(${shot.status})` : ''}
                </span>
              )}
              {shotError && <span className="error">{shotError}</span>}
            </div>
            <pre className="banner-pre">{hitData.banner}</pre>
            {shot?.screenshot && (
              <div className="http-shot" style={{ marginTop: 10 }}>
                <img
                  src={`data:image/png;base64,${shot.screenshot}`}
                  alt="HTTP screenshot"
                  onClick={() => setShotModalOpen(true)}
                  style={{ cursor: 'zoom-in' }}
                />
              </div>
            )}
          </div>
        )}

        {hitData && hitData.version_info && hitData.version_info.length > 0 && (
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

        {hitData && hitData.cves && hitData.cves.length > 0 && (
          <div className="ip-section">
            <p className="ip-section-title mono">CVEs ({hitData.cves.length})</p>
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
                  
                  <a href={'https://nvd.nist.gov/vuln/detail/' + cve.id}
                    target="_blank"
                    rel="noreferrer"
                    className="ip-detail-link"
                    style={{ fontSize: '0.75rem', display: 'inline-flex', alignItems: 'center', gap: 4 }}
                  >
                    NVD <FiArrowUpRight aria-hidden />
                  </a>
                </div>
              ))}
            </div>
          </div>
        )}

        <div className="ip-section">
          <p className="ip-section-title mono">Pivot to</p>
          <div className="ip-actions">
            {pivotLinks(ip).map(({ href, label }) => (
              <a
                key={label}
                href={href}
                target="_blank"
                rel="noreferrer"
                className="ghost small"
                style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}
              >
                {label} <FiArrowUpRight aria-hidden />
              </a>
            ))}
          </div>
        </div>

      </div>
      {shotModalOpen && shot?.screenshot && (
        <div className="shot-modal-backdrop" onClick={() => setShotModalOpen(false)}>
          <div className="shot-modal" onClick={(e) => e.stopPropagation()}>
            <img src={`data:image/png;base64,${shot.screenshot}`} alt="HTTP screenshot enlarged" />
          </div>
        </div>
      )}
    </div>
  )
}
