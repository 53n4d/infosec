import { useEffect, useState } from 'react'
import { useParams, useLocation, useNavigate } from 'react-router-dom'
import {
  TbArrowLeft, TbAlertTriangle, TbArrowUpRight, TbCamera,
  TbShieldCheck, TbShieldX, TbShieldOff, TbFileText, TbLock,
} from 'react-icons/tb'
import {
  fetchIpInfo, fetchHttpScreenshot,
  fetchTlsCert, fetchRobotsTxt, fetchSecurityTxt,
} from '../api'

// ─── helpers ─────────────────────────────────────────────────────────────────

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
    { href: 'https://www.shodan.io/host/'             + ip, label: 'Shodan'      },
    { href: 'https://www.virustotal.com/gui/ip-address/' + ip, label: 'VirusTotal' },
    { href: 'https://bgp.he.net/ip/'                  + ip, label: 'BGP.he.net'  },
    { href: 'https://viz.greynoise.io/ip/'            + ip, label: 'GreyNoise'   },
    { href: 'https://www.abuseipdb.com/check/'        + ip, label: 'AbuseIPDB'   },
    { href: 'https://www.censys.io/hosts/'            + ip, label: 'Censys'      },
    // ── crt.sh: search certificate transparency logs for this IP ────────
    { href: 'https://crt.sh/?q='                      + encodeURIComponent(ip), label: 'crt.sh' },
  ]
}

// ── TLS expiry colour logic (shared with ScanConsole badge) ──────────────────
export function tlsExpiryColor(daysLeft) {
  if (daysLeft === null || daysLeft === undefined) return 'var(--dim)'
  if (daysLeft < 0)   return 'var(--crit)'   // expired
  if (daysLeft < 14)  return 'var(--high)'   // < 2 weeks
  if (daysLeft < 30)  return 'var(--med)'    // < 1 month
  return 'var(--low)'                         // healthy
}

// ── TLS section sub-component ─────────────────────────────────────────────────
function TlsSection({ ip, port }) {
  const [tls,     setTls]     = useState(null)
  const [loading, setLoading] = useState(true)
  const [error,   setError]   = useState('')

  useEffect(() => {
    setLoading(true)
    setError('')
    fetchTlsCert(ip, port)
      .then(setTls)
      .catch(e => setError(e.message))
      .finally(() => setLoading(false))
  }, [ip, port])

  if (loading) return <p className="hint" style={{ marginTop: 8 }}>Fetching TLS cert…</p>
  if (error)   return (
    <p className="hint" style={{ marginTop: 8, color: 'var(--dim)' }}>
      TLS: {error}
    </p>
  )
  if (!tls || tls.error) return (
    <p className="hint" style={{ marginTop: 8, color: 'var(--dim)' }}>
      No TLS cert ({tls?.error || 'no response'})
    </p>
  )

  const expiryColor = tlsExpiryColor(tls.days_left)
  const StatusIcon  = tls.expired
    ? TbShieldX
    : tls.self_signed
      ? TbShieldOff
      : TbShieldCheck

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      {/* Status row */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
        <StatusIcon
          size={15}
          style={{ color: tls.expired ? 'var(--crit)' : tls.self_signed ? 'var(--med)' : 'var(--low)', flexShrink: 0 }}
        />
        <span className="mono" style={{ fontSize: '0.82rem', color: 'var(--text)' }}>
          {tls.subject_cn || '(no CN)'}
        </span>
        {tls.self_signed && (
          <span className="badge" style={{ color: 'var(--med)', borderColor: 'var(--med)', background: 'rgba(255,170,0,0.08)' }}>
            SELF-SIGNED
          </span>
        )}
        {tls.expired && (
          <span className="badge" style={{ color: 'var(--crit)', borderColor: 'var(--crit)', background: 'rgba(255,50,50,0.08)' }}>
            EXPIRED
          </span>
        )}
      </div>

      {/* Validity */}
      <div className="ip-detail-grid" style={{ gridTemplateColumns: '1fr 1fr 1fr', gap: 10, marginBottom: 0 }}>
        <div className="ip-field">
          <span className="ip-label">Issuer</span>
          <span className="ip-value">{tls.issuer_cn || tls.issuer_org || '—'}</span>
        </div>
        <div className="ip-field">
          <span className="ip-label">Expires</span>
          <span className="ip-value mono" style={{ color: expiryColor }}>
            {tls.not_after
              ? `${tls.not_after.slice(0, 11).trim()} (${
                  tls.days_left !== null
                    ? tls.days_left < 0
                      ? `${Math.abs(tls.days_left)}d ago`
                      : `${tls.days_left}d left`
                    : '?'
                })`
              : '—'}
          </span>
        </div>
        <div className="ip-field">
          <span className="ip-label">Valid From</span>
          <span className="ip-value mono">{tls.not_before ? tls.not_before.slice(0, 11).trim() : '—'}</span>
        </div>
      </div>

      {/* SANs */}
      {tls.sans && tls.sans.length > 0 && (
        <div className="ip-field">
          <span className="ip-label">SANs ({tls.sans.length})</span>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5, marginTop: 4 }}>
            {tls.sans.slice(0, 12).map(san => (
              <span key={san} className="version-tag" style={{ fontFamily: 'var(--mono-font)', fontSize: '0.72rem' }}>
                {san}
              </span>
            ))}
            {tls.sans.length > 12 && (
              <span className="hint" style={{ fontSize: '0.7rem' }}>+{tls.sans.length - 12} more</span>
            )}
          </div>
        </div>
      )}

      {/* crt.sh link */}
      <a
        href={`https://crt.sh/?q=${encodeURIComponent(tls.subject_cn || ip)}`}
        target="_blank"
        rel="noreferrer"
        className="ip-detail-link"
        style={{ display: 'inline-flex', alignItems: 'center', gap: 4, marginTop: 2 }}
      >
        Search crt.sh for this cert <TbArrowUpRight size={12} aria-hidden />
      </a>
    </div>
  )
}

// ── Recon text section (robots / security.txt) ────────────────────────────────
function ReconTextSection({ ip, port, scheme }) {
  const [robots,   setRobots]   = useState(null)
  const [secTxt,   setSecTxt]   = useState(null)
  const [loading,  setLoading]  = useState(true)
  const [expanded, setExpanded] = useState({ robots: false, sec: false })

  useEffect(() => {
    setLoading(true)
    Promise.allSettled([
      fetchRobotsTxt({ ip, port, scheme }),
      fetchSecurityTxt({ ip, port, scheme }),
    ]).then(([r, s]) => {
      setRobots(r.status === 'fulfilled' ? r.value : { found: false, error: r.reason?.message })
      setSecTxt(s.status === 'fulfilled' ? s.value : { found: false, error: s.reason?.message })
    }).finally(() => setLoading(false))
  }, [ip, port, scheme])

  if (loading) return <p className="hint" style={{ marginTop: 8 }}>Fetching recon files…</p>

  const neitherFound = !robots?.found && !secTxt?.found
  if (neitherFound) return (
    <p className="hint" style={{ marginTop: 8, color: 'var(--dim)' }}>
      Neither robots.txt nor security.txt found on this host.
    </p>
  )

  const textareaStyle = {
    fontFamily: 'var(--mono-font)',
    fontSize: '0.75rem',
    color: 'var(--text2)',
    background: 'var(--bg3)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius)',
    padding: '10px 12px',
    whiteSpace: 'pre-wrap',
    wordBreak: 'break-word',
    lineHeight: 1.55,
    marginTop: 8,
    maxHeight: 220,
    overflowY: 'auto',
  }

  function FileBlock({ label, data, expandKey }) {
    if (!data?.found) return (
      <div>
        <span className="ip-label">{label}</span>
        <span className="hint" style={{ marginLeft: 8, fontSize: '0.72rem' }}>
          {data?.error ? `error: ${data.error}` : `not found (HTTP ${data?.status ?? '—'})`}
        </span>
      </div>
    )
    const lines    = (data.content || '').split('\n')
    const preview  = lines.slice(0, 8).join('\n')
    const isLong   = lines.length > 8
    const isOpen   = expanded[expandKey]

    return (
      <div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span className="ip-label">{label}</span>
          <span className="badge" style={{ color: 'var(--low)', borderColor: 'var(--low)', background: 'rgba(100,220,100,0.07)' }}>
            {lines.length} lines
          </span>
          {isLong && (
            <button
              className="ghost small"
              style={{ padding: '1px 8px', fontSize: '0.67rem' }}
              onClick={() => setExpanded(e => ({ ...e, [expandKey]: !e[expandKey] }))}
            >
              {isOpen ? 'collapse' : 'expand all'}
            </button>
          )}
        </div>
        <pre style={textareaStyle}>
          {isOpen ? data.content : preview}
          {isLong && !isOpen && '\n…'}
        </pre>
      </div>
    )
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <FileBlock label="robots.txt"    data={robots} expandKey="robots" />
      <FileBlock label="security.txt"  data={secTxt} expandKey="sec"    />
    </div>
  )
}

// ── Main component ─────────────────────────────────────────────────────────────
export default function IpDetail() {
  const { ip }     = useParams()
  const location   = useLocation()
  const navigate   = useNavigate()

  const [hitData, setHitData] = useState(location.state?.hit || null)

  useEffect(() => {
    if (hitData) return
    let attempts = 0
    const poll = setInterval(() => {
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i)
        if (key && key.startsWith('hit_' + ip + '_')) {
          try {
            const parsed = JSON.parse(localStorage.getItem(key))
            if (parsed) { setHitData(parsed); clearInterval(poll); return }
          } catch { /* ignore */ }
        }
      }
      attempts++
      if (attempts >= 10) clearInterval(poll)
    }, 50)
    return () => clearInterval(poll)
  }, [ip, hitData])

  const [geo,           setGeo]           = useState(null)
  const [geoError,      setGeoError]      = useState('')
  const [geoLoading,    setGeoLoading]    = useState(true)
  const [shot,          setShot]          = useState(null)
  const [shotLoading,   setShotLoading]   = useState(false)
  const [shotError,     setShotError]     = useState('')
  const [shotModalOpen, setShotModalOpen] = useState(false)

  useEffect(() => {
    if (!ip) return
    setGeoLoading(true)
    setGeoError('')
    fetchIpInfo(ip)
      .then(data => {
        if (data.status === 'fail') setGeoError(data.message || 'Lookup failed')
        else setGeo(data)
      })
      .catch(err => setGeoError(err.message))
      .finally(() => setGeoLoading(false))
  }, [ip])

  const tlsPorts   = hitData ? [443, 8443].filter(p => p === hitData.port) : []
  const isTlsPort  = hitData && [443, 8443].includes(hitData.port)

  // Determine scheme for recon text fetch
  const httpPort   = hitData?.port
  const httpScheme = [443, 8443].includes(httpPort) ? 'https' : 'http'
  const isHttpPort = hitData && [80, 443, 8080, 8443, 8000, 8008, 8888, 3000, 5000].includes(httpPort)

  const canScreenshot = isHttpPort

  const grabScreenshot = async () => {
    if (!canScreenshot) return
    setShotLoading(true)
    setShotError('')
    try {
      const scheme = [443, 8443].includes(hitData.port) ? 'https' : 'http'
      const data   = await fetchHttpScreenshot({ ip, port: hitData.port, scheme, full_page: false })
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
          <button
            className="back-link"
            onClick={() => {
              if (window.opener) window.close()
              else if (window.history.length > 1) navigate(-1)
              else navigate('/scan')
            }}
          >
            <TbArrowLeft size={13} /> Back
          </button>
          <p className="eyebrow" style={{
            fontFamily: 'var(--mono-font)',
            fontSize: '0.65rem',
            color: 'var(--cyan)',
            letterSpacing: '0.18em',
            textTransform: 'uppercase',
            marginTop: 4,
            marginBottom: 8,
          }}>
            IP Intelligence
          </p>
          <h1 className="ip-title">{ip}</h1>
          {hitData && (
            <div className="ip-hit-meta">
              <span
                style={{
                  display: 'inline-block',
                  width: 7,
                  height: 7,
                  borderRadius: '50%',
                  background: 'var(--low)',
                  boxShadow: '0 0 6px var(--low)',
                  marginRight: 8,
                  flexShrink: 0,
                }}
                aria-hidden
              />
              <span className="mono" style={{ fontSize: '0.82rem', color: 'var(--cyan)' }}>
                port {hitData.port} open
              </span>
              {hitData.software && (
                <span className="hit-software" style={{ marginLeft: 10 }}>{hitData.software}</span>
              )}
            </div>
          )}
        </div>

        {/* ── Geolocation / ASN ── */}
        <div className="ip-section">
          <p className="ip-section-title">Geolocation / ASN</p>
          {geoLoading && <p className="hint">Resolving…</p>}
          {geoError && (
            <p className="error" style={{ marginTop: 8 }}>
              <TbAlertTriangle size={14} aria-label="warning" /> {geoError}
            </p>
          )}
          {geo && (
            <div className="ip-detail-grid">
              {geoRows.map(([label, value]) => (
                <div className="ip-field" key={label}>
                  <span className="ip-label">{label}</span>
                  <span className="ip-value">{value}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* ── Banner ── */}
        {hitData && hitData.banner && (
          <div className="ip-section">
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap', marginBottom: 12 }}>
              <p className="ip-section-title" style={{ margin: 0 }}>
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
                  <TbCamera size={12} />
                  {shotLoading ? 'Capturing…' : 'Screenshot'}
                </button>
              )}
              {shot && shot.title && (
                <span className="hint" style={{ color: 'var(--cyan)' }}>
                  {shot.title} {shot.status ? `(${shot.status})` : ''}
                </span>
              )}
              {shotError && (
                <span className="error" style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
                  <TbAlertTriangle size={12} /> {shotError}
                </span>
              )}
            </div>
            <pre className="banner-pre">{hitData.banner}</pre>
            {shot?.screenshot && (
              <div className="screenshot-wrap" style={{ marginTop: 12 }}>
                <img
                  src={`data:image/png;base64,${shot.screenshot}`}
                  alt="HTTP screenshot"
                  onClick={() => setShotModalOpen(true)}
                  style={{ cursor: 'zoom-in', width: '100%', display: 'block' }}
                />
              </div>
            )}
          </div>
        )}

        {/* ── TLS Certificate (auto-shown for port 443 / 8443) ── */}
        {isTlsPort && (
          <div className="ip-section">
            <p className="ip-section-title">
              <TbLock size={11} style={{ marginRight: 5 }} aria-hidden />
              TLS Certificate — port {hitData.port}
            </p>
            <TlsSection ip={ip} port={hitData.port} />
          </div>
        )}

        {/* ── Detected software ── */}
        {hitData && hitData.version_info && hitData.version_info.length > 0 && (
          <div className="ip-section">
            <p className="ip-section-title">Detected software</p>
            <div className="version-tags">
              {hitData.version_info.map((vi, i) => (
                <span key={i} className="version-tag">
                  <span className="mono">{vi.label}</span> {vi.value}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* ── CVEs ── */}
        {hitData && hitData.cves && hitData.cves.length > 0 && (
          <div className="ip-section">
            <p className="ip-section-title">CVEs ({hitData.cves.length})</p>
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
                    href={'https://nvd.nist.gov/vuln/detail/' + cve.id}
                    target="_blank"
                    rel="noreferrer"
                    className="ip-detail-link"
                    style={{ display: 'inline-flex', alignItems: 'center', gap: 4, marginTop: 6 }}
                  >
                    NVD <TbArrowUpRight size={12} aria-hidden />
                  </a>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ── robots.txt + security.txt (HTTP ports) ── */}
        {isHttpPort && (
          <div className="ip-section">
            <p className="ip-section-title">
              <TbFileText size={11} style={{ marginRight: 5 }} aria-hidden />
              Recon Files
            </p>
            <ReconTextSection ip={ip} port={httpPort} scheme={httpScheme} />
          </div>
        )}

        {/* ── Pivot links ── */}
        <div className="ip-section">
          <p className="ip-section-title">Pivot to</p>
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
                {label} <TbArrowUpRight size={12} aria-hidden />
              </a>
            ))}
          </div>
        </div>

      </div>

      {/* ── Screenshot modal ── */}
      {shotModalOpen && shot?.screenshot && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0,0,0,0.85)',
            zIndex: 600,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            cursor: 'zoom-out',
          }}
          onClick={() => setShotModalOpen(false)}
        >
          <div
            style={{ maxWidth: '90vw', maxHeight: '90vh', overflow: 'auto' }}
            onClick={e => e.stopPropagation()}
          >
            <img
              src={`data:image/png;base64,${shot.screenshot}`}
              alt="HTTP screenshot enlarged"
              style={{ display: 'block', maxWidth: '100%' }}
            />
          </div>
        </div>
      )}
    </div>
  )
}