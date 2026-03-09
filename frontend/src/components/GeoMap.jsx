import { useEffect, useRef, useState, useCallback, useMemo } from 'react'
import { FiX } from 'react-icons/fi'

// ─── Simplified continent outlines (lng,lat) ──────────────────────────────────
const LAND_PATHS = [
  // North America
  "M -168,72 L -140,60 L -125,50 L -117,32 L -110,23 L -90,16 L -83,10 L -77,8 L -75,18 L -68,22 L -60,46 L -64,48 L -67,47 L -70,43 L -82,42 L -83,46 L -88,48 L -90,47 L -93,49 L -97,49 L -101,49 L -110,49 L -115,49 L -120,49 L -124,49 L -124,46 L -126,50 L -130,55 L -134,58 L -137,60 L -139,60 L -141,68 L -155,70 L -158,72 L -168,72 Z",
  // Greenland
  "M -72,76 L -60,82 L -44,83 L -32,78 L -28,70 L -45,60 L -58,62 L -68,66 L -72,76 Z",
  // South America
  "M -80,10 L -75,8 L -68,6 L -60,5 L -52,5 L -44,2 L -40,-4 L -36,-10 L -40,-22 L -44,-24 L -38,-15 L -42,-20 L -50,-30 L -52,-34 L -58,-38 L -64,-42 L -68,-46 L -70,-54 L -68,-56 L -64,-52 L -62,-48 L -56,-44 L -50,-40 L -48,-26 L -42,-16 L -38,-8 L -40,-4 L -44,2 L -52,5 L -58,3 L -62,1 L -68,2 L -74,4 L -78,8 L -80,10 Z",
  // Europe
  "M -10,36 L 0,36 L 4,40 L 10,44 L 14,44 L 18,40 L 24,38 L 28,42 L 30,46 L 26,50 L 20,54 L 18,58 L 22,60 L 24,66 L 20,68 L 16,70 L 14,68 L 10,56 L 6,54 L 2,54 L 0,58 L 4,64 L 2,70 L -2,68 L -4,62 L -2,58 L -6,54 L -10,50 L -8,44 L -10,36 Z",
  // Africa
  "M -18,16 L -10,8 L 0,5 L 10,5 L 20,8 L 32,16 L 40,20 L 44,12 L 44,4 L 42,-4 L 38,-16 L 32,-28 L 26,-34 L 18,-36 L 10,-26 L 4,-16 L -2,-8 L -12,0 L -18,10 L -18,16 Z",
  // Asia
  "M 26,42 L 36,36 L 44,36 L 56,24 L 60,22 L 68,24 L 72,20 L 72,10 L 80,10 L 88,22 L 92,26 L 100,20 L 104,10 L 110,20 L 120,22 L 130,32 L 140,40 L 142,46 L 140,52 L 134,46 L 128,48 L 122,52 L 116,48 L 110,42 L 100,40 L 90,44 L 80,46 L 74,48 L 68,52 L 60,58 L 50,58 L 44,54 L 38,52 L 32,48 L 26,42 Z",
  // Australia
  "M 114,-22 L 120,-18 L 130,-14 L 138,-16 L 146,-20 L 150,-24 L 152,-28 L 148,-34 L 140,-38 L 132,-34 L 124,-30 L 118,-28 L 114,-22 Z",
  // Japan
  "M 130,32 L 134,34 L 140,38 L 144,42 L 140,44 L 136,38 L 130,32 Z",
  // UK
  "M -6,50 L 0,52 L 2,58 L -2,60 L -6,56 L -6,50 Z",
  // Indonesia
  "M 96,4 L 100,2 L 106,0 L 110,-2 L 116,-4 L 120,-4 L 124,-2 L 128,-2 L 130,0 L 128,2 L 124,2 L 118,0 L 112,0 L 106,2 L 100,4 L 96,4 Z",
]

// ─── Helpers ──────────────────────────────────────────────────────────────────

function countryFlag(code) {
  if (!code || code.length !== 2) return '🌐'
  const offset = 0x1F1E6 - 65
  return String.fromCodePoint(code.toUpperCase().charCodeAt(0) + offset) +
         String.fromCodePoint(code.toUpperCase().charCodeAt(1) + offset)
}

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

// ─── Component ────────────────────────────────────────────────────────────────

export default function GeoMap({ points = [], onClose }) {
  const W = 960, H = 500, MARGIN = 20
  const svgRef = useRef(null)

  const [tooltip,       setTooltip]       = useState(null)
  const [hovered,       setHovered]       = useState(null)
  const [selected,      setSelected]      = useState(null)
  const [transform,     setTransform]     = useState({ x: 0, y: 0, k: 1 })
  const [dragging,      setDragging]      = useState(null)
  const [sidebarFilter, setSidebarFilter] = useState('')

  // ESC to close
  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') onClose?.() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  // Derived stats
  const countryCounts = useMemo(() =>
    points.reduce((acc, p) => {
      const k = p.country || 'Unknown'
      acc[k] = (acc[k] || 0) + 1
      return acc
    }, {}), [points])

  const topCountries = useMemo(() =>
    Object.entries(countryCounts).sort((a, b) => b[1] - a[1]).slice(0, 5),
    [countryCounts])

  const topPort = useMemo(() => {
    const pc = points.reduce((acc, p) => {
      if (p.port) acc[p.port] = (acc[p.port] || 0) + 1
      return acc
    }, {})
    return Object.entries(pc).sort((a, b) => b[1] - a[1])[0]
  }, [points])

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

  // ── Zoom ──────────────────────────────────────────────────────────────────
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
        k: newK,
        x: cx - (cx - t.x) * (newK / t.k),
        y: cy - (cy - t.y) * (newK / t.k),
      }
    })
  }, [])

  useEffect(() => {
    const el = svgRef.current
    if (!el) return
    el.addEventListener('wheel', handleWheel, { passive: false })
    return () => el.removeEventListener('wheel', handleWheel)
  }, [handleWheel])

  // ── Drag ──────────────────────────────────────────────────────────────────
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

  // ── Fly-to ────────────────────────────────────────────────────────────────
  const flyTo = (point) => {
    setSelected(point.ip)
    const j = ipJitter(point.ip)
    const { x, y } = projectLL(point.lat + j.dy, point.lon + j.dx, W, H, MARGIN)
    setTransform({ x: 300 - x * 2.5, y: 250 - y * 2.5, k: 2.5 })
  }

  return (
    <div className="gm-backdrop" onClick={(e) => { if (e.target === e.currentTarget) onClose?.() }}>
      <div className="gm-modal">

        {/* ── Header ── */}
        <div className="gm-header">
          <div className="gm-header-left">
            <span className="gm-dot" />
            <span className="gm-title mono">GEO MAP</span>
            <span className="gm-sub mono">
              {points.length} host{points.length !== 1 ? 's' : ''} · {Object.keys(countryCounts).length} countr{Object.keys(countryCounts).length !== 1 ? 'ies' : 'y'}
            </span>
          </div>

          <div className="gm-badges">
            {topCountries.map(([country, count]) => {
              const code = points.find(p => p.country === country)?.countryCode
              return (
                <span key={country} className="gm-badge">
                  {countryFlag(code)} {country} <b>{count}</b>
                </span>
              )
            })}
            {topPort && (
              <span className="gm-badge gm-badge--port">
                :{topPort[0]} <b>{topPort[1]}×</b>
              </span>
            )}
          </div>

          <button className="ghost small gm-close" onClick={onClose} title="Close (ESC)">
            <FiX size={15} />
          </button>
        </div>

        {/* ── Body ── */}
        <div className="gm-body">

          {/* Map canvas */}
          <div className="gm-map-wrap">
            <svg
              ref={svgRef}
              viewBox={`0 0 ${W} ${H}`}
              className="gm-svg"
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
                  <feMerge>
                    <feMergeNode in="blur" />
                    <feMergeNode in="SourceGraphic" />
                  </feMerge>
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

                {/* Ocean */}
                <rect x={0} y={0} width={W} height={H} fill="url(#gm-ocean)" />

                {/* Graticule grid */}
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

                {/* Latitude labels */}
                {[80, 60, 40, 20, 0, -20, -40, -60].map(lat => {
                  const { y } = projectLL(lat, -175, W, H, MARGIN)
                  return (
                    <text key={lat} x={MARGIN + 2} y={y - 2}
                      fontSize="7" fill="#1e4060" fontFamily="monospace">
                      {lat}°
                    </text>
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
                      fill="var(--accent)" fillOpacity="0.45"
                      fontFamily="monospace"
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
                  const color = isSel ? '#ffdd00' : isHov ? '#ffffff' : 'var(--accent)'
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
                      <circle className="gm-ring"  cx={x} cy={y} r={5}
                        fill="none" stroke={color} strokeWidth="1"   strokeOpacity="0.5" />
                      <circle className="gm-ring2" cx={x} cy={y} r={5}
                        fill="none" stroke={color} strokeWidth="0.5" strokeOpacity="0.3" />
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

            {/* Hover tooltip */}
            {tooltip && (
              <div className="gm-tooltip" style={{
                left: Math.min(tooltip.x + 14, 680),
                top:  Math.max(tooltip.y - 10, 10),
              }}>
                <div className="gm-tip-ip mono">{tooltip.point.ip}</div>

                {tooltip.point.port && (
                  <div className="gm-tip-row">
                    <span className="gm-tip-label mono">PORT</span>
                    <span className="mono" style={{ color: 'var(--accent)' }}>{tooltip.point.port}</span>
                    {tooltip.point.software && (
                      <span className="gm-tip-soft mono">{tooltip.point.software}</span>
                    )}
                  </div>
                )}
                <div className="gm-tip-row">
                  <span className="gm-tip-label mono">COUNTRY</span>
                  <span className="mono">{countryFlag(tooltip.point.countryCode)} {tooltip.point.country || '—'}</span>
                </div>
                {tooltip.point.city && (
                  <div className="gm-tip-row">
                    <span className="gm-tip-label mono">CITY</span>
                    <span className="mono">{tooltip.point.city}</span>
                  </div>
                )}
                {tooltip.point.isp && (
                  <div className="gm-tip-row">
                    <span className="gm-tip-label mono">ISP</span>
                    <span className="gm-tip-dim mono">{tooltip.point.isp}</span>
                  </div>
                )}
                {tooltip.point.org && tooltip.point.org !== tooltip.point.isp && (
                  <div className="gm-tip-row">
                    <span className="gm-tip-label mono">ORG</span>
                    <span className="gm-tip-dim mono">{tooltip.point.org}</span>
                  </div>
                )}
                <div className="gm-tip-row">
                  <span className="gm-tip-label mono">LAT/LON</span>
                  <span className="gm-tip-coords mono">
                    {tooltip.point.lat?.toFixed(3)}, {tooltip.point.lon?.toFixed(3)}
                  </span>
                </div>
              </div>
            )}

            <p className="gm-hint mono">scroll to zoom · drag to pan · click pin to select</p>
          </div>

          {/* ── Sidebar ── */}
          <aside className="gm-sidebar">
            <div className="gm-sidebar-head">
              <span className="mono" style={{ fontSize: '0.7rem', color: 'var(--accent)', letterSpacing: 2 }}>
                HOSTS
              </span>
              <span className="mono hint">{points.length}</span>
            </div>

            <input
              className="gm-sidebar-search"
              placeholder="Filter IP / country…"
              value={sidebarFilter}
              onChange={e => setSidebarFilter(e.target.value)}
            />

            <div className="gm-sidebar-list">
              {filteredPoints.map((p) => (
                <div
                  key={p.ip}
                  className={[
                    'gm-sidebar-row',
                    selected === p.ip ? 'gm-sidebar-row--selected' : '',
                    hovered  === p.ip ? 'gm-sidebar-row--hovered'  : '',
                  ].filter(Boolean).join(' ')}
                  onClick={() => flyTo(p)}
                  onMouseEnter={() => setHovered(p.ip)}
                  onMouseLeave={() => setHovered(null)}
                >
                  <div className="gm-sidebar-row-top">
                    <span className="gm-sidebar-ip mono">{p.ip}</span>
                    {p.port && <span className="gm-sidebar-port mono">:{p.port}</span>}
                  </div>
                  <div className="gm-sidebar-meta mono">
                    {countryFlag(p.countryCode)}{p.city ? ` ${p.city},` : ''} {p.country || '—'}
                  </div>
                  {p.software && (
                    <div className="gm-sidebar-sw mono">{p.software}</div>
                  )}
                </div>
              ))}

              {filteredPoints.length === 0 && (
                <p className="hint mono" style={{ padding: '12px', fontSize: '0.75rem' }}>
                  no matches
                </p>
              )}
            </div>
          </aside>

        </div>
      </div>
    </div>
  )
}