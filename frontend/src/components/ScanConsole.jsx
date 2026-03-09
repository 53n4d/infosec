import { useState, useEffect, useRef, useCallback, useMemo } from 'react'
import { useLocation, useNavigate, useParams } from 'react-router-dom'
import {
  FiAlertTriangle,
  FiArrowUpRight,
  FiCamera,
  FiDownload,
  FiFilter,
  FiGlobe,
  FiLock,
  FiPlay,
  FiRefreshCw,
  FiSearch,
  FiShare2,
  FiX,
  FiZap,
} from 'react-icons/fi'
import { startScan, streamScanJob, fetchCountries, fetchIpInfo } from '../api'
import { contributeCountryIntel } from '../intel'

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const PRESET_PORTS = [21, 22, 23, 25, 80, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 9200, 27017]

const ALL_PORTS = [
  { port: 21,    label: 'FTP' },
  { port: 22,    label: 'SSH' },
  { port: 23,    label: 'Telnet' },
  { port: 25,    label: 'SMTP' },
  { port: 53,    label: 'DNS' },
  { port: 80,    label: 'HTTP' },
  { port: 110,   label: 'POP3' },
  { port: 111,   label: 'RPCbind' },
  { port: 135,   label: 'MS-RPC' },
  { port: 139,   label: 'NetBIOS' },
  { port: 143,   label: 'IMAP' },
  { port: 161,   label: 'SNMP' },
  { port: 389,   label: 'LDAP' },
  { port: 443,   label: 'HTTPS' },
  { port: 445,   label: 'SMB' },
  { port: 465,   label: 'SMTPS' },
  { port: 512,   label: 'rexec' },
  { port: 513,   label: 'rlogin' },
  { port: 514,   label: 'rsh/syslog' },
  { port: 587,   label: 'SMTP-Sub' },
  { port: 636,   label: 'LDAPS' },
  { port: 993,   label: 'IMAPS' },
  { port: 995,   label: 'POP3S' },
  { port: 1433,  label: 'MSSQL' },
  { port: 1521,  label: 'Oracle' },
  { port: 2049,  label: 'NFS' },
  { port: 2375,  label: 'Docker' },
  { port: 2376,  label: 'Docker-TLS' },
  { port: 2377,  label: 'Docker-Swarm' },
  { port: 3000,  label: 'Dev/Grafana' },
  { port: 3306,  label: 'MySQL' },
  { port: 3389,  label: 'RDP' },
  { port: 4444,  label: 'Metasploit' },
  { port: 5432,  label: 'PostgreSQL' },
  { port: 5601,  label: 'Kibana' },
  { port: 5672,  label: 'RabbitMQ' },
  { port: 5900,  label: 'VNC' },
  { port: 5984,  label: 'CouchDB' },
  { port: 6379,  label: 'Redis' },
  { port: 6443,  label: 'K8s API' },
  { port: 7001,  label: 'WebLogic' },
  { port: 8000,  label: 'HTTP-Alt' },
  { port: 8008,  label: 'HTTP-Alt2' },
  { port: 8080,  label: 'HTTP-Proxy' },
  { port: 8088,  label: 'HTTP-Alt3' },
  { port: 8443,  label: 'HTTPS-Alt' },
  { port: 8888,  label: 'Jupyter' },
  { port: 9000,  label: 'SonarQube' },
  { port: 9090,  label: 'Prometheus' },
  { port: 9092,  label: 'Kafka' },
  { port: 9100,  label: 'Node Exporter' },
  { port: 9200,  label: 'Elasticsearch' },
  { port: 9300,  label: 'ES-Cluster' },
  { port: 10000, label: 'Webmin' },
  { port: 10250, label: 'Kubelet' },
  { port: 11211, label: 'Memcached' },
  { port: 15672, label: 'RabbitMQ-Mgmt' },
  { port: 27017, label: 'MongoDB' },
  { port: 27018, label: 'MongoDB-Alt' },
  { port: 50070, label: 'Hadoop' },
]

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

function severityColor(score) {
  const n = parseFloat(score)
  if (isNaN(n)) return 'var(--dim)'
  if (n >= 9.0) return 'var(--crit)'
  if (n >= 7.0) return 'var(--high)'
  if (n >= 4.0) return 'var(--med)'
  return 'var(--low)'
}

function hitMaxScore(hit) {
  if (!hit.cves?.length) return 0
  return Math.max(...hit.cves.map(c => parseFloat(c.score || '0') || 0))
}

function matchesPortService(hit, term) {
  const t = term.trim().toLowerCase()
  if (!t) return true
  const portNum = Number(t)
  if (!Number.isNaN(portNum)) return hit.port === portNum
  return (
    (hit.software && hit.software.toLowerCase().includes(t)) ||
    (hit.banner   && hit.banner.toLowerCase().includes(t))
  )
}

function countryFlag(code) {
  if (!code || code.length !== 2) return '🌐'
  const offset = 0x1F1E6 - 65
  return String.fromCodePoint(code.toUpperCase().charCodeAt(0) + offset) +
         String.fromCodePoint(code.toUpperCase().charCodeAt(1) + offset)
}

// ─────────────────────────────────────────────────────────────────────────────
// GeoMap — full-screen modal with world map, tooltips, sidebar, zoom/pan
// ─────────────────────────────────────────────────────────────────────────────

// Simplified continent outlines in [lon, lat] pairs encoded as SVG path strings
const LAND_PATHS = [
  "M -168,72 L -140,60 L -125,50 L -117,32 L -110,23 L -90,16 L -83,10 L -77,8 L -75,18 L -68,22 L -60,46 L -64,48 L -67,47 L -70,43 L -82,42 L -83,46 L -88,48 L -90,47 L -93,49 L -97,49 L -101,49 L -110,49 L -115,49 L -120,49 L -124,49 L -124,46 L -126,50 L -130,55 L -134,58 L -137,60 L -139,60 L -141,68 L -155,70 L -158,72 L -168,72 Z",
  "M -72,76 L -60,82 L -44,83 L -32,78 L -28,70 L -45,60 L -58,62 L -68,66 L -72,76 Z",
  "M -80,10 L -75,8 L -68,6 L -60,5 L -52,5 L -44,2 L -40,-4 L -36,-10 L -40,-22 L -44,-24 L -38,-15 L -42,-20 L -50,-30 L -52,-34 L -58,-38 L -64,-42 L -68,-46 L -70,-54 L -68,-56 L -64,-52 L -62,-48 L -56,-44 L -50,-40 L -48,-26 L -42,-16 L -38,-8 L -40,-4 L -44,2 L -52,5 L -58,3 L -62,1 L -68,2 L -74,4 L -78,8 L -80,10 Z",
  "M -10,36 L 0,36 L 4,40 L 10,44 L 14,44 L 18,40 L 24,38 L 28,42 L 30,46 L 26,50 L 20,54 L 18,58 L 22,60 L 24,66 L 20,68 L 16,70 L 14,68 L 10,56 L 6,54 L 2,54 L 0,58 L 4,64 L 2,70 L -2,68 L -4,62 L -2,58 L -6,54 L -10,50 L -8,44 L -10,36 Z",
  "M -18,16 L -10,8 L 0,5 L 10,5 L 20,8 L 32,16 L 40,20 L 44,12 L 44,4 L 42,-4 L 38,-16 L 32,-28 L 26,-34 L 18,-36 L 10,-26 L 4,-16 L -2,-8 L -12,0 L -18,10 L -18,16 Z",
  "M 26,42 L 36,36 L 44,36 L 56,24 L 60,22 L 68,24 L 72,20 L 72,10 L 80,10 L 88,22 L 92,26 L 100,20 L 104,10 L 110,20 L 120,22 L 130,32 L 140,40 L 142,46 L 140,52 L 134,46 L 128,48 L 122,52 L 116,48 L 110,42 L 100,40 L 90,44 L 80,46 L 74,48 L 68,52 L 60,58 L 50,58 L 44,54 L 38,52 L 32,48 L 26,42 Z",
  "M 114,-22 L 120,-18 L 130,-14 L 138,-16 L 146,-20 L 150,-24 L 152,-28 L 148,-34 L 140,-38 L 132,-34 L 124,-30 L 118,-28 L 114,-22 Z",
  "M 130,32 L 134,34 L 140,38 L 144,42 L 140,44 L 136,38 L 130,32 Z",
  "M -6,50 L 0,52 L 2,58 L -2,60 L -6,56 L -6,50 Z",
  "M 96,4 L 100,2 L 106,0 L 110,-2 L 116,-4 L 120,-4 L 124,-2 L 128,-2 L 130,0 L 128,2 L 124,2 L 118,0 L 112,0 L 106,2 L 100,4 L 96,4 Z",
]

function projectLL(lat, lon, w, h, margin = 0) {
  const x = ((lon + 180) / 360) * (w - 2 * margin) + margin
  const y = ((90  - lat) / 180) * (h - 2 * margin) + margin
  return { x, y }
}

function projectPath(pathStr, w, h, margin) {
  return pathStr.replace(/(-?\d+(?:\.\d+)?),(-?\d+(?:\.\d+)?)/g, (_, lon, lat) => {
    const { x, y } = projectLL(parseFloat(lat), parseFloat(lon), w, h, margin)
    return `${x.toFixed(1)},${y.toFixed(1)}`
  })
}

function ipJitter(ip) {
  let h = 0
  for (let i = 0; i < ip.length; i++) h = (h * 31 + ip.charCodeAt(i)) >>> 0
  const angle = (h % 360) * (Math.PI / 180)
  const r = 0.4 + ((h >> 10) % 30) / 100
  return { dx: Math.cos(angle) * r, dy: Math.sin(angle) * r }
}

function GeoMap({ points = [], onClose }) {
  const W = 960, H = 500, MARGIN = 20
  const svgRef   = useRef(null)
  const [tooltip,       setTooltip]       = useState(null)
  const [hovered,       setHovered]       = useState(null)
  const [selected,      setSelected]      = useState(null)
  const [transform,     setTransform]     = useState({ x: 0, y: 0, k: 1 })
  const [dragging,      setDragging]      = useState(null)
  const [sidebarFilter, setSidebarFilter] = useState('')

  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') onClose?.() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  const countryCounts = useMemo(() =>
    points.reduce((acc, p) => {
      const k = p.country || 'Unknown'
      acc[k] = (acc[k] || 0) + 1
      return acc
    }, {}), [points])

  const topCountries = useMemo(() =>
    Object.entries(countryCounts).sort((a, b) => b[1] - a[1]).slice(0, 5), [countryCounts])

  const portCounts = useMemo(() =>
    points.reduce((acc, p) => {
      if (p.port) acc[p.port] = (acc[p.port] || 0) + 1
      return acc
    }, {}), [points])
  const topPort = Object.entries(portCounts).sort((a, b) => b[1] - a[1])[0]

  const projectedPaths = useMemo(() =>
    LAND_PATHS.map(p => projectPath(p, W, H, MARGIN)), [])

  const filteredPoints = useMemo(() =>
    sidebarFilter
      ? points.filter(p =>
          p.ip.includes(sidebarFilter) ||
          (p.country || '').toLowerCase().includes(sidebarFilter.toLowerCase()) ||
          (p.city    || '').toLowerCase().includes(sidebarFilter.toLowerCase()))
      : points,
    [points, sidebarFilter])

  // ── Zoom ──────────────────────────────────────────────────────────────
  const handleWheel = useCallback((e) => {
    e.preventDefault()
    const delta = e.deltaY > 0 ? 0.85 : 1.18
    setTransform(t => {
      const newK = Math.max(0.8, Math.min(8, t.k * delta))
      const rect = svgRef.current?.getBoundingClientRect()
      if (!rect) return { ...t, k: newK }
      const cx = e.clientX - rect.left
      const cy = e.clientY - rect.top
      return {
        k:  newK,
        x:  cx - (cx - t.x) * (newK / t.k),
        y:  cy - (cy - t.y) * (newK / t.k),
      }
    })
  }, [])

  useEffect(() => {
    const el = svgRef.current
    if (!el) return
    el.addEventListener('wheel', handleWheel, { passive: false })
    return () => el.removeEventListener('wheel', handleWheel)
  }, [handleWheel])

  // ── Drag ──────────────────────────────────────────────────────────────
  const startDrag = (e) => {
    if (e.button !== 0) return
    setDragging({ startX: e.clientX, startY: e.clientY, tx: transform.x, ty: transform.y })
  }
  const onDrag = (e) => {
    if (!dragging) return
    setTransform(t => ({
      ...t,
      x: dragging.tx + (e.clientX - dragging.startX),
      y: dragging.ty + (e.clientY - dragging.startY),
    }))
  }
  const endDrag = () => setDragging(null)

  const flyTo = (point) => {
    setSelected(point.ip)
    const j = ipJitter(point.ip)
    const { x, y } = projectLL(point.lat + j.dy, point.lon + j.dx, W, H, MARGIN)
    setTransform({ x: 300 - x * 2.5, y: 250 - y * 2.5, k: 2.5 })
  }

  return (
    <div className="geomap-backdrop" onClick={(e) => { if (e.target === e.currentTarget) onClose?.() }}>
      <div className="geomap-modal">

        {/* Header */}
        <div className="geomap-header">
          <div className="geomap-header-left">
            <span className="geomap-header-dot" />
            <span className="geomap-title">GEO MAP</span>
            <span className="geomap-sub">
              {points.length} host{points.length !== 1 ? 's' : ''} · {Object.keys(countryCounts).length} countr{Object.keys(countryCounts).length !== 1 ? 'ies' : 'y'}
            </span>
          </div>
          <div className="geomap-badges">
            {topCountries.map(([country, count]) => {
              const code = points.find(p => p.country === country)?.countryCode
              return (
                <span key={country} className="geomap-badge">
                  {countryFlag(code)} {country} <b>{count}</b>
                </span>
              )
            })}
            {topPort && (
              <span className="geomap-badge geomap-badge-port">
                :{topPort[0]} <b>{topPort[1]}×</b>
              </span>
            )}
          </div>
          <button className="geomap-close" onClick={onClose} title="Close (ESC)">
            <FiX size={16} />
          </button>
        </div>

        {/* Body */}
        <div className="geomap-body">

          {/* Map */}
          <div className="geomap-map-wrap">
            <svg
              ref={svgRef}
              viewBox={`0 0 ${W} ${H}`}
              className="geomap-svg"
              onMouseDown={startDrag}
              onMouseMove={onDrag}
              onMouseUp={endDrag}
              onMouseLeave={endDrag}
              style={{ cursor: dragging ? 'grabbing' : 'grab' }}
            >
              <defs>
                <radialGradient id="gm-ocean" cx="50%" cy="40%" r="70%">
                  <stop offset="0%"   stopColor="#0a1628" />
                  <stop offset="100%" stopColor="#050d14" />
                </radialGradient>
                <filter id="gm-glow">
                  <feGaussianBlur stdDeviation="2.5" result="blur" />
                  <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
                </filter>
                <style>{`
                  @keyframes gm-pulse {
                    0%   { r: 5;  opacity: 0.7; }
                    100% { r: 20; opacity: 0;   }
                  }
                  .gm-ring  { animation: gm-pulse 2.2s ease-out infinite; }
                  .gm-ring2 { animation: gm-pulse 2.2s ease-out 0.8s infinite; }
                `}</style>
              </defs>

              <g transform={`translate(${transform.x},${transform.y}) scale(${transform.k})`}>
                <rect x={0} y={0} width={W} height={H} fill="url(#gm-ocean)" />

                {/* Graticule */}
                {[...Array(13)].map((_, i) => (
                  <line key={`gv${i}`}
                    x1={(i / 12) * W} y1={0} x2={(i / 12) * W} y2={H}
                    stroke="#1a3a5c" strokeWidth="0.4" strokeOpacity="0.4" />
                ))}
                {[...Array(7)].map((_, i) => (
                  <line key={`gh${i}`}
                    x1={0} y1={(i / 6) * H} x2={W} y2={(i / 6) * H}
                    stroke="#1a3a5c" strokeWidth="0.4" strokeOpacity="0.4" />
                ))}

                {/* Lat labels */}
                {[80, 60, 40, 20, 0, -20, -40, -60].map(lat => {
                  const { y } = projectLL(lat, -175, W, H, MARGIN)
                  return (
                    <text key={lat} x={MARGIN + 2} y={y - 2}
                      fontSize="7" fill="#1e4060" fontFamily="monospace">{lat}°</text>
                  )
                })}

                {/* Landmasses */}
                {projectedPaths.map((d, i) => (
                  <path key={i} d={d} fill="#0e2035" stroke="#1e4060" strokeWidth="0.8" />
                ))}

                {/* Country cluster labels */}
                {topCountries.slice(0, 6).map(([country]) => {
                  const pts = points.filter(p => p.country === country)
                  if (!pts.length) return null
                  const avgLat = pts.reduce((s, p) => s + p.lat, 0) / pts.length
                  const avgLon = pts.reduce((s, p) => s + p.lon, 0) / pts.length
                  const { x, y } = projectLL(avgLat, avgLon, W, H, MARGIN)
                  return (
                    <text key={country} x={x} y={y - 14}
                      textAnchor="middle" fontSize="8"
                      fill="var(--accent)" fillOpacity="0.45" fontFamily="monospace"
                      style={{ pointerEvents: 'none' }}>
                      {country} ×{pts.length}
                    </text>
                  )
                })}

                {/* Host dots */}
                {points.map((p) => {
                  const j = ipJitter(p.ip)
                  const { x, y } = projectLL(p.lat + j.dy, p.lon + j.dx, W, H, MARGIN)
                  const isHov = hovered  === p.ip
                  const isSel = selected === p.ip
                  const color = isSel ? '#ffdd00' : isHov ? '#ffffff' : 'var(--accent, #00ff88)'
                  return (
                    <g key={p.ip}
                      filter="url(#gm-glow)"
                      style={{ cursor: 'pointer' }}
                      onMouseEnter={(e) => {
                        setHovered(p.ip)
                        const rect = svgRef.current.getBoundingClientRect()
                        setTooltip({ x: e.clientX - rect.left, y: e.clientY - rect.top, point: p })
                      }}
                      onMouseLeave={() => { setHovered(null); setTooltip(null) }}
                      onClick={() => setSelected(p.ip === selected ? null : p.ip)}
                    >
                      <circle className="gm-ring"  cx={x} cy={y} r={5}  fill="none" stroke={color} strokeWidth="1"   strokeOpacity="0.5" />
                      <circle className="gm-ring2" cx={x} cy={y} r={5}  fill="none" stroke={color} strokeWidth="0.5" strokeOpacity="0.3" />
                      <circle cx={x} cy={y}
                        r={isHov || isSel ? 5.5 : 3.5}
                        fill={color}
                        fillOpacity={isHov || isSel ? 1 : 0.85}
                        style={{ transition: 'r 0.15s, fill 0.15s' }} />
                    </g>
                  )
                })}
              </g>
            </svg>

            {/* Tooltip */}
            {tooltip && (
              <div className="geomap-tooltip" style={{
                left: Math.min(tooltip.x + 14, 680),
                top:  Math.max(tooltip.y - 10, 10),
              }}>
                <div className="geomap-tip-ip">{tooltip.point.ip}</div>
                {tooltip.point.port && (
                  <div className="geomap-tip-row">
                    <span className="geomap-tip-label">PORT</span>
                    <span style={{ color: 'var(--accent)' }}>{tooltip.point.port}</span>
                    {tooltip.point.software && (
                      <span style={{ color: '#aaa', marginLeft: 6 }}>{tooltip.point.software}</span>
                    )}
                  </div>
                )}
                <div className="geomap-tip-row">
                  <span className="geomap-tip-label">COUNTRY</span>
                  <span>{countryFlag(tooltip.point.countryCode)} {tooltip.point.country || '—'}</span>
                </div>
                {tooltip.point.city && (
                  <div className="geomap-tip-row">
                    <span className="geomap-tip-label">CITY</span>
                    <span>{tooltip.point.city}</span>
                  </div>
                )}
                {tooltip.point.isp && (
                  <div className="geomap-tip-row">
                    <span className="geomap-tip-label">ISP</span>
                    <span style={{ color: '#aaa' }}>{tooltip.point.isp}</span>
                  </div>
                )}
                {tooltip.point.org && tooltip.point.org !== tooltip.point.isp && (
                  <div className="geomap-tip-row">
                    <span className="geomap-tip-label">ORG</span>
                    <span style={{ color: '#aaa' }}>{tooltip.point.org}</span>
                  </div>
                )}
                <div className="geomap-tip-row">
                  <span className="geomap-tip-label">LAT/LON</span>
                  <span style={{ color: '#555' }}>
                    {tooltip.point.lat?.toFixed(3)}, {tooltip.point.lon?.toFixed(3)}
                  </span>
                </div>
              </div>
            )}

            <div className="geomap-hint">scroll to zoom · drag to pan · click pin to highlight</div>
          </div>

          {/* Sidebar */}
          <div className="geomap-sidebar">
            <div className="geomap-sidebar-head">
              <span className="mono" style={{ fontSize: '0.7rem', color: 'var(--accent)', letterSpacing: 2 }}>HOSTS</span>
              <span className="mono" style={{ fontSize: '0.7rem', color: 'var(--dim)' }}>{points.length}</span>
            </div>
            <input
              className="geomap-sidebar-search"
              placeholder="Filter IP / country…"
              value={sidebarFilter}
              onChange={e => setSidebarFilter(e.target.value)}
            />
            <div className="geomap-sidebar-list">
              {filteredPoints.map((p) => (
                <div
                  key={p.ip}
                  className={`geomap-sidebar-row ${selected === p.ip ? 'selected' : ''} ${hovered === p.ip ? 'hovered' : ''}`}
                  onClick={() => flyTo(p)}
                  onMouseEnter={() => setHovered(p.ip)}
                  onMouseLeave={() => setHovered(null)}
                >
                  <div className="geomap-sidebar-row-top">
                    <span className="geomap-sidebar-ip">{p.ip}</span>
                    {p.port && <span className="geomap-sidebar-port">:{p.port}</span>}
                  </div>
                  <div className="geomap-sidebar-meta">
                    {countryFlag(p.countryCode)} {p.city ? `${p.city}, ` : ''}{p.country || '—'}
                  </div>
                  {p.software && <div className="geomap-sidebar-sw">{p.software}</div>}
                </div>
              ))}
              {filteredPoints.length === 0 && (
                <p style={{ padding: '12px', color: 'var(--dim)', fontSize: '0.75rem', fontFamily: 'monospace' }}>
                  no matches
                </p>
              )}
            </div>
          </div>

        </div>
      </div>
    </div>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// Main ScanConsole component
// ─────────────────────────────────────────────────────────────────────────────

export default function ScanConsole() {
  const location  = useLocation()
  const navigate  = useNavigate()
  const { jobId: urlJobId } = useParams()

  // ── Country ───────────────────────────────────────────────────────────
  const [countries,     setCountries]     = useState([])
  const [country,       setCountry]       = useState('')
  const [countryName,   setCountryName]   = useState('')
  const [countryInput,  setCountryInput]  = useState('')
  const [countryLocked, setCountryLocked] = useState(false)
  const [pickerOpen,    setPickerOpen]    = useState(false)

  const filteredCountries = useMemo(() => {
    const term = countryInput.toLowerCase()
    if (!term.trim()) return countries
    return countries.filter(
      c => c.code.toLowerCase().includes(term) || c.name.toLowerCase().includes(term)
    )
  }, [countries, countryInput])

  const commitCountry = (code, name) => {
    const found = name
      ? { code, name }
      : countries.find(c => c.code === code)
    setCountry(code)
    setCountryName(found?.name || code)
    setCountryInput(found ? `${found.code} - ${found.name}` : code)
    setPickerOpen(false)
  }

  useEffect(() => {
    fetchCountries()
      .then(data => {
        setCountries(data)
        if (data.length && !location.state?.country && !urlJobId) {
          commitCountry(data[0].code, data[0].name)
        }
      })
      .catch(() => {})
  }, [])

  // ── Scan config ───────────────────────────────────────────────────────
  const [ranges,          setRanges]          = useState('')
  const [portMode,        setPortMode]        = useState('preset')
  const [customPorts,     setCustomPorts]     = useState([])
  const [portSearch,      setPortSearch]      = useState('')
  const [portDropOpen,    setPortDropOpen]    = useState(false)
  const portDropRef = useRef(null)
  const [scanMode,        setScanMode]        = useState('wide')
  const [runCve,          setRunCve]          = useState(true)
  const [masscanRate,     setMasscanRate]     = useState(1000)
  const [nmapParallelism, setNmapParallelism] = useState(100)

  // ── Job state ─────────────────────────────────────────────────────────
  const [jobId,       setJobId]       = useState(urlJobId || null)
  const [jobStatus,   setJobStatus]   = useState(null)
  const [stats,       setStats]       = useState({ probed: 0, responsive: 0, vuln_hosts: 0 })
  const [hits,        setHits]        = useState([])
  const [error,       setError]       = useState('')
  const [activeHit,   setActiveHit]   = useState(null)
  const [intelBanner, setIntelBanner] = useState(null)

  // ── Filters + selection ───────────────────────────────────────────────
  const [onlyFindings,      setOnlyFindings]      = useState(true)
  const [portServiceFilter, setPortServiceFilter] = useState('')
  const [severityFilter,    setSeverityFilter]    = useState('all')
  const [selectedIPs,       setSelectedIPs]       = useState(new Set())

  // ── Geo map ───────────────────────────────────────────────────────────
  const [geoPoints,  setGeoPoints]  = useState([])
  const [geoLoading, setGeoLoading] = useState(false)
  const [geoError,   setGeoError]   = useState('')
  const [geoMapOpen, setGeoMapOpen] = useState(false)

  const esRef  = useRef(null)
  const logRef = useRef(null)

  // ── Severity filter helper ────────────────────────────────────────────
  const passesSeverity = (hit) => {
    if (severityFilter === 'all') return true
    const maxScore = hitMaxScore(hit)
    if (severityFilter === 'critical') return maxScore >= 9.0
    if (severityFilter === 'high')     return maxScore >= 7.0
    return true
  }

  const visibleHits = useMemo(() => {
    const base = onlyFindings
      ? hits.filter(h => h.status !== 'silent' && h.port > 0)
      : hits
    return base
      .filter(hit => matchesPortService(hit, portServiceFilter))
      .filter(passesSeverity)
  }, [hits, onlyFindings, portServiceFilter, severityFilter])

  // ── Selection helpers ─────────────────────────────────────────────────
  const toggleSelectIP = (ip) =>
    setSelectedIPs(prev => {
      const next = new Set(prev)
      next.has(ip) ? next.delete(ip) : next.add(ip)
      return next
    })

  const visibleUniqueIPs = useMemo(() =>
    [...new Set(visibleHits.map(h => h.ip))], [visibleHits])

  const selectAllVisible = () => setSelectedIPs(new Set(visibleUniqueIPs))
  const clearSelection   = () => setSelectedIPs(new Set())

  const rescanSelected = () => {
    if (selectedIPs.size === 0) return
    navigate('/scan/new', {
      state: { ranges: Array.from(selectedIPs).join('\n'), country, countryName },
    })
  }

  // ── Export ────────────────────────────────────────────────────────────
  const exportResults = (format) => {
    const rows = visibleHits.map(h => ({
      ip:        h.ip,
      port:      h.port,
      status:    h.status,
      software:  h.software  || '',
      banner:    h.banner    || '',
      cve_count: h.cves?.length || 0,
      max_cvss:  hitMaxScore(h),
      range:     h.range     || '',
    }))
    if (format === 'json') {
      const blob = new Blob([JSON.stringify(rows, null, 2)], { type: 'application/json' })
      const a = Object.assign(document.createElement('a'), {
        href:     URL.createObjectURL(blob),
        download: `scan-${jobId || 'results'}.json`,
      })
      a.click()
      URL.revokeObjectURL(a.href)
      return
    }
    const header = ['ip', 'port', 'status', 'software', 'banner', 'cve_count', 'max_cvss', 'range']
    const csv = [header.join(','), ...rows.map(r =>
      header.map(k => `"${String(r[k]).replace(/"/g, '""')}"`).join(',')
    )].join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const a = Object.assign(document.createElement('a'), {
      href:     URL.createObjectURL(blob),
      download: `scan-${jobId || 'results'}.csv`,
    })
    a.click()
    URL.revokeObjectURL(a.href)
  }

  // ── Geo map builder ───────────────────────────────────────────────────
  const buildGeoMap = async () => {
    const uniqueIps = [...new Set(visibleHits.map(h => h.ip))].slice(0, 200)
    setGeoLoading(true)
    setGeoError('')
    const points = []
    for (const ip of uniqueIps) {
      try {
        const info = await fetchIpInfo(ip)
        if (info?.lat != null && info?.lon != null) {
          points.push({
            ip,
            lat:         info.lat,
            lon:         info.lon,
            country:     info.country,
            countryCode: info.countryCode,
            city:        info.city,
            isp:         info.isp,
            org:         info.org,
            port:        visibleHits.find(h => h.ip === ip)?.port,
            software:    visibleHits.find(h => h.ip === ip)?.software,
          })
        }
      } catch (e) {
        setGeoError(e.message)
        break
      }
    }
    setGeoPoints(points)
    setGeoLoading(false)
    if (points.length > 0) setGeoMapOpen(true)
  }

  // ── Firestore contribution ────────────────────────────────────────────
  const _contributeToFirestore = (jid, savedMeta) => {
    try {
      const countryCode = savedMeta?.country
      if (!countryCode) return
      const hitList = []
      for (let i = 0; i < localStorage.length; i++) {
        const k = localStorage.key(i)
        if (k?.startsWith('hit_')) {
          try { hitList.push(JSON.parse(localStorage.getItem(k))) } catch { /* ignore */ }
        }
      }
      contributeCountryIntel(countryCode, {
        country_name: savedMeta.countryName || '',
        ranges:       savedMeta.ranges      || [],
        probed:       savedMeta.probed      || 0,
        open:         savedMeta.open        || 0,
        vulns:        savedMeta.vulns       || 0,
        hits:         hitList.slice(0, 500),
      })
        .then(() => console.log('[intel] ✓ contributed:', countryCode))
        .catch(e => console.warn('[intel] failed:', e.message))
    } catch (e) {
      console.warn('[intel] error:', e.message)
    }
  }

  // ── Start scan ────────────────────────────────────────────────────────
  const finalPorts = () => {
    if (portMode === 'all')    return []
    if (portMode === 'preset') return PRESET_PORTS
    return customPorts
  }

  const handleStart = async (e) => {
    e.preventDefault()
    setError('')
    setHits([])
    setSelectedIPs(new Set())
    setStats({ probed: 0, responsive: 0, vuln_hosts: 0 })
    setJobStatus(null)
    setJobId(null)
    setActiveHit(null)
    setIntelBanner(null)

    const rangeList = ranges.split(/[\s,\n]+/).map(r => r.trim()).filter(Boolean)
    if (!rangeList.length) { setError('Enter at least one CIDR range.'); return }
    if (portMode === 'custom' && customPorts.length === 0) {
      setError('Add at least one port in Custom mode.'); return
    }

    try {
      const { job_id } = await startScan({
        ranges:           rangeList,
        ports:            finalPorts(),
        all_ports:        portMode === 'all',
        run_cve:          runCve,
        masscan_rate:     masscanRate,
        scan_mode:        scanMode,
        nmap_parallelism: nmapParallelism,
      })
      localStorage.setItem('scan_' + job_id, JSON.stringify({
        jobId: job_id, country, countryName,
        ranges: rangeList, rangesText: ranges,
        startedAt: Date.now(), status: 'running',
        probed: 0, open: 0, vulns: 0,
        scan_mode: scanMode, nmap_parallelism: nmapParallelism, masscan_rate: masscanRate,
      }))
      navigate('/scan/' + job_id, { replace: true })
    } catch (err) {
      setError(err.message)
    }
  }

  const handleStop = () => {
    esRef.current?.close()
    setJobStatus('stopped')
    if (jobId) {
      const existing = JSON.parse(localStorage.getItem('scan_' + jobId) || '{}')
      localStorage.setItem('scan_' + jobId, JSON.stringify({ ...existing, status: 'stopped' }))
    }
  }

  // ── Port helpers ──────────────────────────────────────────────────────
  const toggleCustomPort = (port) =>
    setCustomPorts(prev =>
      prev.includes(port) ? prev.filter(p => p !== port) : [...prev, port].sort((a, b) => a - b))

  const removeCustomPort = (port) =>
    setCustomPorts(prev => prev.filter(p => p !== port))

  const addCustomPortByInput = (val) => {
    const n = parseInt(val, 10)
    if (n > 0 && n <= 65535 && !customPorts.includes(n))
      setCustomPorts(prev => [...prev, n].sort((a, b) => a - b))
    setPortSearch('')
  }

  const handlePortSearchKey = (e) => {
    if ((e.key === 'Enter' || e.key === ',') && portSearch.trim()) {
      e.preventDefault()
      addCustomPortByInput(portSearch.trim())
    }
  }

  const filteredPortList = useMemo(() => {
    const term = portSearch.toLowerCase().trim()
    if (!term) return ALL_PORTS
    return ALL_PORTS.filter(p =>
      p.port.toString().includes(term) || p.label.toLowerCase().includes(term))
  }, [portSearch])

  // ── Navigation state (from RangeLookup / rescan) ──────────────────────
  useEffect(() => {
    if (!location.state) return
    const { ranges: r, country: c, countryName: cn, intelHits, intelCountry, age_days } = location.state
    if (r) setRanges(r)
    if (c) {
      setCountry(c)
      setCountryName(cn || c)
      setCountryInput(cn ? `${c} - ${cn}` : c)
      setCountryLocked(true)
    }
    if (intelHits?.length > 0) {
      setHits(intelHits)
      setStats({
        probed: 0,
        responsive: intelHits.length,
        vuln_hosts: intelHits.filter(h => h.cves?.length > 0).length,
      })
      setJobStatus('intel')
      setIntelBanner({ country: intelCountry || c, age_days: age_days || 0 })
    }
    window.history.replaceState({}, '')
  }, [location.state])

  // ── Reconnect to existing job from URL ────────────────────────────────
  useEffect(() => {
    if (!urlJobId) return

    try {
      const saved = JSON.parse(localStorage.getItem('scan_' + urlJobId) || '{}')
      if (saved.rangesText)       setRanges(saved.rangesText)
      if (saved.scan_mode)        setScanMode(saved.scan_mode)
      if (saved.nmap_parallelism) setNmapParallelism(saved.nmap_parallelism)
      if (saved.masscan_rate)     setMasscanRate(saved.masscan_rate)
      if (saved.country) {
        setCountry(saved.country)
        setCountryName(saved.countryName || saved.country)
        setCountryInput(
          saved.countryName ? `${saved.country} - ${saved.countryName}` : saved.country)
        setCountryLocked(true)
      }
    } catch { /* ignore */ }

    setJobId(urlJobId)
    setJobStatus('running')
    setHits([])
    setStats({ probed: 0, responsive: 0, vuln_hosts: 0 })
    setIntelBanner(null)
    esRef.current?.close()

    esRef.current = streamScanJob(
      urlJobId,
      (event) => {
        if (event.type === 'hit') {
          const hit = event.hit
          setHits(prev => [...prev, hit])
          if (hit.ip && hit.port)
            localStorage.setItem('hit_' + hit.ip + '_' + hit.port, JSON.stringify(hit))
        } else if (event.type === 'stats') {
          setStats({ probed: event.probed, responsive: event.responsive, vuln_hosts: event.vuln_hosts })
          setJobStatus(event.status)
          const existing = JSON.parse(localStorage.getItem('scan_' + urlJobId) || '{}')
          localStorage.setItem('scan_' + urlJobId, JSON.stringify({
            ...existing, status: event.status,
            probed: event.probed, open: event.responsive, vulns: event.vuln_hosts,
          }))
        }
      },
      () => {
        setJobStatus('done')
        const existing = JSON.parse(localStorage.getItem('scan_' + urlJobId) || '{}')
        const updated = { ...existing, status: 'done' }
        localStorage.setItem('scan_' + urlJobId, JSON.stringify(updated))
        _contributeToFirestore(urlJobId, updated)
      },
      () => {
        setJobStatus('error')
        const existing = JSON.parse(localStorage.getItem('scan_' + urlJobId) || '{}')
        localStorage.setItem('scan_' + urlJobId, JSON.stringify({ ...existing, status: 'error' }))
      },
    )
    return () => esRef.current?.close()
  }, [urlJobId])

  // ── Misc effects ──────────────────────────────────────────────────────
  useEffect(() => {
    const handler = (e) => {
      if (portDropRef.current && !portDropRef.current.contains(e.target))
        setPortDropOpen(false)
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight
  }, [hits])

  useEffect(() => () => esRef.current?.close(), [])

  // ─────────────────────────────────────────────────────────────────────
  // Render
  // ─────────────────────────────────────────────────────────────────────
  return (
    <div className="scan-shell">

      {/* ── GeoMap modal (portal-like, rendered at top level) ── */}
      {geoMapOpen && geoPoints.length > 0 && (
        <GeoMap points={geoPoints} onClose={() => setGeoMapOpen(false)} />
      )}

      {/* ── Left sidebar: config ── */}
      <aside className="scan-config">
        <div className="scan-config-header">
          <button className="back-link" onClick={() => navigate('/scan')}>← Scan Console</button>
          <p className="mono">
            {scanMode === 'deep' ? 'deep → os → vuln → firestore' : 'wide → banner → nvd → firestore'}
          </p>
          <h2>Scan {urlJobId ? urlJobId.slice(0, 8) + '…' : 'New'}</h2>
        </div>

        <form className="form" onSubmit={handleStart}>

          {/* Country */}
          <div className="field">
            <label>
              Country{' '}
              <span style={{ color: 'var(--dim)', fontWeight: 400, marginLeft: 6 }}>(intel contribution)</span>
            </label>
            {countryLocked ? (
              <div style={{
                display: 'flex', alignItems: 'center', gap: 10,
                background: 'var(--bg3)', border: '1px solid var(--border)',
                borderRadius: 'var(--radius)', padding: '8px 12px',
              }}>
                <span className="mono" style={{ color: 'var(--accent)', fontSize: '1rem' }}>{country}</span>
                <span style={{ color: 'var(--fg)', flex: 1 }}>{countryName}</span>
                <span style={{ fontSize: '0.7rem', color: 'var(--dim)', display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                  <FiLock size={11} /> tied to ranges
                </span>
              </div>
            ) : (
              <div className="combo" style={{ position: 'relative' }}>
                <input
                  value={countryInput}
                  onChange={(e) => { setCountryInput(e.target.value); setPickerOpen(true) }}
                  onFocus={() => setPickerOpen(true)}
                  onBlur={() => setTimeout(() => setPickerOpen(false), 120)}
                  placeholder="Search country…"
                />
                {pickerOpen && filteredCountries.length > 0 && (
                  <div className="combo-list">
                    {filteredCountries.slice(0, 12).map(c => (
                      <button key={c.code} type="button" className="combo-item"
                        onMouseDown={e => e.preventDefault()}
                        onClick={() => commitCountry(c.code, c.name)}>
                        <span className="mono">{c.code}</span><span>{c.name}</span>
                      </button>
                    ))}
                  </div>
                )}
              </div>
            )}
            {country && (
              <p className="hint mono" style={{
                color: 'var(--accent)', fontSize: '0.72rem', marginTop: 4,
                display: 'inline-flex', alignItems: 'center', gap: 5,
              }}>
                <FiShare2 size={11} /> results will be contributed to community intel for {country}
              </p>
            )}
          </div>

          {/* Ranges */}
          <div className="field">
            <label>Target ranges (CIDR, one per line)</label>
            <textarea rows={5} value={ranges} onChange={e => setRanges(e.target.value)}
              placeholder={'192.168.1.0/24\n10.0.0.0/8'} spellCheck={false} />
            <p className="hint">
              {ranges.trim()
                ? `${ranges.trim().split(/\n/).filter(Boolean).length} range(s) loaded`
                : 'Paste CIDRs or use Range Pull to populate'}
            </p>
          </div>

          {/* Scan mode */}
          <div className="field">
            <label>Scan mode</label>
            <div className="scan-mode-row">
              <button type="button"
                title="Fast port discovery across large IP ranges"
                className={`scan-mode-btn ${scanMode === 'wide' ? 'selected' : ''}`}
                onClick={() => setScanMode('wide')}>
                <FiZap size={15} />
                <span className="scan-mode-title">Wide Scan</span>
              </button>
              <button type="button"
                title="Slow but more accurate — service detection, OS fingerprint, vuln scripts"
                className={`scan-mode-btn ${scanMode === 'deep' ? 'selected' : ''}`}
                onClick={() => setScanMode('deep')}>
                <FiSearch size={15} />
                <span className="scan-mode-title">Deep Scan</span>
              </button>
            </div>
            {scanMode === 'deep' && (
              <p className="hint" style={{ color: 'var(--high)', marginTop: 6, display: 'inline-flex', alignItems: 'center', gap: 5 }}>
                <FiAlertTriangle size={12} /> Slow but more accurate — use on small ranges or selected IPs only
              </p>
            )}
          </div>

          {/* Port mode */}
          <div className="field">
            <label>Port mode</label>
            <div className="pill-row">
              {[
                { id: 'preset', label: 'CVE Preset' },
                { id: 'custom', label: 'Custom' },
                { id: 'all',    label: 'All Ports' },
              ].map(m => (
                <button key={m.id} type="button"
                  className={portMode === m.id ? 'pill selected' : 'pill'}
                  onClick={() => setPortMode(m.id)}>
                  {m.label}
                </button>
              ))}
            </div>

            {portMode === 'preset' && (
              <p className="hint mono" style={{ fontSize: '0.72rem', marginTop: 6 }}>
                {PRESET_PORTS.join(', ')}
              </p>
            )}

            {portMode === 'custom' && (
              <div className="port-custom-wrap" ref={portDropRef}>
                {/* Selected port chips */}
                {customPorts.length > 0 && (
                  <div className="port-chips">
                    {customPorts.map(p => (
                      <span key={p} className="port-chip port-chip-hit">
                        {p}
                        <button type="button" onClick={() => removeCustomPort(p)}
                          style={{ marginLeft: 4, background: 'none', border: 'none', color: 'inherit', cursor: 'pointer', padding: 0, lineHeight: 1 }}>
                          ×
                        </button>
                      </span>
                    ))}
                  </div>
                )}
                {/* Port search + dropdown */}
                <div style={{ position: 'relative' }}>
                  <input
                    value={portSearch}
                    onChange={e => { setPortSearch(e.target.value); setPortDropOpen(true) }}
                    onFocus={() => setPortDropOpen(true)}
                    onKeyDown={handlePortSearchKey}
                    placeholder="Search or type port number…"
                    style={{ width: '100%' }}
                  />
                  {portDropOpen && (
                    <div className="combo-list" style={{ maxHeight: 180 }}>
                      {filteredPortList.slice(0, 20).map(p => (
                        <button key={p.port} type="button" className="combo-item"
                          onMouseDown={e => e.preventDefault()}
                          onClick={() => { toggleCustomPort(p.port); setPortSearch(''); setPortDropOpen(false) }}>
                          <span className="mono">{p.port}</span>
                          <span style={{ color: 'var(--dim)' }}>{p.label}</span>
                          {customPorts.includes(p.port) && (
                            <span style={{ marginLeft: 'auto', color: 'var(--accent)' }}>✓</span>
                          )}
                        </button>
                      ))}
                      {filteredPortList.length === 0 && portSearch.trim() && (
                        <button type="button" className="combo-item"
                          onMouseDown={e => e.preventDefault()}
                          onClick={() => addCustomPortByInput(portSearch.trim())}>
                          <span className="mono">{portSearch.trim()}</span>
                          <span style={{ color: 'var(--dim)' }}>Add custom port</span>
                        </button>
                      )}
                    </div>
                  )}
                </div>
              </div>
            )}

            {portMode === 'all' && (
              <p className="hint" style={{ color: 'var(--high)', marginTop: 6, display: 'inline-flex', alignItems: 'center', gap: 5 }}>
                <FiAlertTriangle size={12} /> Scans all 65535 ports — very slow on large ranges
              </p>
            )}
          </div>

          {/* Rate */}
          <div className="field">
            <label>Rate (pps) max 100,000</label>
            <input type="number" min={100} max={100000}
              value={masscanRate}
              onChange={e => setMasscanRate(Number(e.target.value))} />
            {masscanRate > 2000 && (
              <p className="hint" style={{ color: 'var(--high)', marginTop: 4, display: 'inline-flex', alignItems: 'center', gap: 5 }}>
                <FiAlertTriangle size={12} /> High rate may miss hosts. Recommended: 500–2000 pps.
              </p>
            )}
          </div>

          {/* CVE lookup */}
          <div className="switch-row">
            <label>
              <input type="checkbox" checked={runCve} onChange={e => setRunCve(e.target.checked)} />
              NVD CVE lookup per banner
            </label>
          </div>

          {/* Actions */}
          <div className="form-actions">
            <button type="submit" className="primary"
              disabled={jobStatus === 'running'}
              style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
              {jobStatus === 'running'
                ? <><FiRefreshCw size={14} className="spin" /> Scanning…</>
                : <><FiPlay size={14} /> Start Scan</>}
            </button>
            {jobStatus === 'running' && (
              <button type="button" className="ghost" onClick={handleStop}>■ Stop</button>
            )}
          </div>
        </form>

        {/* Stats */}
        <div className="scan-stats">
          <div className="stat-mini">
            <span className="mono">probed</span>
            <strong>{stats.probed.toLocaleString()}</strong>
          </div>
          <div className="stat-mini">
            <span className="mono">open</span>
            <strong style={{ color: 'var(--accent)' }}>{stats.responsive.toLocaleString()}</strong>
          </div>
          <div className="stat-mini">
            <span className="mono">vulns</span>
            <strong style={{ color: 'var(--high)' }}>{stats.vuln_hosts.toLocaleString()}</strong>
          </div>
        </div>

        {jobId && (
          <p className="hint mono" style={{ marginTop: 8, wordBreak: 'break-all' }}>
            job: {jobId}
          </p>
        )}
        {jobStatus && !['running', 'intel'].includes(jobStatus) && (
          <p className={`scan-status-badge ${jobStatus}`}>{jobStatus.toUpperCase()}</p>
        )}
        {error && <p className="error">{error}</p>}
      </aside>

      {/* ── Right panel: hit stream ── */}
      <div className="scan-main">

        {/* Intel banner */}
        {intelBanner && (
          <div className="intel-scan-banner">
            <FiZap size={13} style={{ color: 'var(--accent)', marginRight: 6 }} />
            Community data for {intelBanner.country}
            {intelBanner.age_days > 0 ? ` — scanned ${intelBanner.age_days}d ago` : ' — fresh'}
            <button className="ghost small" style={{ marginLeft: 16, fontSize: '0.75rem' }}
              onClick={() => {
                setIntelBanner(null)
                setHits([])
                setStats({ probed: 0, responsive: 0, vuln_hosts: 0 })
                setJobStatus(null)
              }}>
              Clear — run fresh scan
            </button>
          </div>
        )}

        {/* Toolbar */}
        {hits.length > 0 && (
          <div className="hit-toolbar">
            <div className="hit-filter-fields">
              <label className="hit-filter-input">
                <FiFilter size={14} />
                <input
                  value={portServiceFilter}
                  onChange={e => setPortServiceFilter(e.target.value)}
                  placeholder="Filter by port or service (e.g. 22, 443, redis)"
                />
              </label>
              <label className="hit-filter-select">
                Severity
                <select value={severityFilter} onChange={e => setSeverityFilter(e.target.value)}>
                  <option value="all">All</option>
                  <option value="high">High+</option>
                  <option value="critical">Critical</option>
                </select>
              </label>
            </div>

            <label className="hit-filter-toggle" title="Show only hosts with banner/software/CVEs">
              <input type="checkbox" checked={onlyFindings}
                onChange={e => { setOnlyFindings(e.target.checked); setSelectedIPs(new Set()) }} />
              <span>Only findings</span>
              <span className="hit-filter-count">
                {onlyFindings ? `${visibleHits.length} / ${hits.length}` : `all ${hits.length}`}
              </span>
            </label>

            <div className="hit-toolbar-sep" />

            <button className="ghost small" onClick={selectAllVisible}>Select all</button>
            {selectedIPs.size > 0 && (
              <>
                <button className="ghost small" onClick={clearSelection}>
                  Clear ({selectedIPs.size})
                </button>
                <button className="primary small" onClick={rescanSelected}
                  style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
                  <FiPlay size={11} /> Re-scan {selectedIPs.size} IP{selectedIPs.size > 1 ? 's' : ''}
                </button>
              </>
            )}

            <div className="hit-toolbar-sep" />

            <div className="hit-export-group">
              <button className="ghost small" onClick={() => exportResults('csv')}>
                <FiDownload size={13} /> CSV
              </button>
              <button className="ghost small" onClick={() => exportResults('json')}>
                <FiDownload size={13} /> JSON
              </button>
            </div>

            <button className="ghost small" onClick={buildGeoMap} disabled={geoLoading}
              style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
              <FiGlobe size={13} />
              {geoLoading ? 'Mapping…' : 'Geo map'}
            </button>
          </div>
        )}

        {geoError && (
          <p className="error" style={{ margin: '8px 16px' }}>{geoError}</p>
        )}

        {/* Hit stream */}
        <div className="hit-stream" ref={logRef}>
          {hits.length === 0 && (
            <div className="hit-empty">
              {jobStatus === 'running'
                ? <><span className="pulse-dot" /> waiting for open ports…</>
                : 'No hits yet. Configure and start a scan, or load community intel from the dashboard.'}
            </div>
          )}

          {(() => {
            // Group hits by IP
            const grouped = {}
            for (const hit of visibleHits) {
              if (!grouped[hit.ip]) grouped[hit.ip] = []
              grouped[hit.ip].push(hit)
            }

            return Object.entries(grouped).map(([ip, ports]) => {
              const isActive  = activeHit === ip
              const isSelected = selectedIPs.has(ip)
              const allCves   = ports.flatMap(p => p.cves || [])
              const topCveScore = allCves.length
                ? Math.max(...allCves.map(c => parseFloat(c.score || '0') || 0))
                : 0

              return (
                <div key={ip}
                  className={`hit-row ${isActive ? 'active' : ''} ${isSelected ? 'selected' : ''}`}
                  onClick={() => setActiveHit(isActive ? null : ip)}>

                  <div className="hit-row-main">
                    <input type="checkbox" className="hit-checkbox"
                      checked={isSelected}
                      onClick={e => e.stopPropagation()}
                      onChange={() => toggleSelectIP(ip)} />

                    <span className="status-dot open" />

                    <span className="mono hit-ip"
                      style={{ color: 'var(--accent)', fontWeight: 600, minWidth: 130 }}>
                      {ip}
                    </span>

                    <span className="hit-ports">
                      {ports.every(p => p.status === 'silent')
                        ? <span className="hint" style={{ fontSize: '0.72rem', marginLeft: 4 }}>no response</span>
                        : ports.map((p, pi) => {
                            const hasData = !!(p.banner || p.software || p.cves?.length)
                            return (
                              <span key={pi}
                                className={`port-chip ${hasData ? 'port-chip-hit' : ''}`}
                                title={p.software || (p.banner ? p.banner.slice(0, 80) : 'no banner')}>
                                {p.port}
                                {p.software && (
                                  <span className="port-chip-svc">{p.software.split(' ')[0]}</span>
                                )}
                              </span>
                            )
                          })
                      }
                    </span>

                    {allCves.length > 0 && (
                      <span className="cve-badge"
                        style={{ color: severityColor(topCveScore), borderColor: severityColor(topCveScore) }}>
                        {allCves.length} CVE{allCves.length > 1 ? 's' : ''}
                      </span>
                    )}
                  </div>

                  {isActive && (
                    <div className="hit-detail">
                      {ports.map((p, pi) => (
                        <div key={pi} className="hit-port-section">
                          <div className="hit-port-section-header">
                            <span className="mono" style={{ color: 'var(--accent)' }}>:{p.port}</span>
                            {p.software && <span className="hit-software">{p.software}</span>}
                            {!p.banner && !p.software && (
                              <span className="hint" style={{ fontSize: '0.72rem' }}>no banner</span>
                            )}
                          </div>
                          {p.banner && <pre className="banner-pre">{p.banner}</pre>}
                          {p.version_info?.length > 0 && (
                            <div className="version-tags">
                              {p.version_info.map((vi, j) => (
                                <span key={j} className="version-tag">
                                  <span className="mono">{vi.label}</span> {vi.value}
                                </span>
                              ))}
                            </div>
                          )}
                          {p.cves?.length > 0 && (
                            <div className="cve-detail-list">
                              {p.cves.map((cve, j) => (
                                <div key={j} className="cve-detail-item">
                                  <div className="cve-detail-head">
                                    <span className="badge strong">{cve.id}</span>
                                    <span className="score-pill"
                                      style={{ color: severityColor(cve.score) }}>
                                      CVSS {cve.score} — {cve.severity}
                                    </span>
                                  </div>
                                  <p className="cve-desc">{cve.desc}</p>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      ))}
                      <button className="ip-detail-link"
                        onClick={e => {
                          e.stopPropagation()
                          navigate('/ip/' + encodeURIComponent(ip), { state: { hit: ports[0] } })
                        }}
                        style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                        View IP detail <FiArrowUpRight size={13} />
                      </button>
                    </div>
                  )}
                </div>
              )
            })
          })()}
        </div>
      </div>
    </div>
  )
}