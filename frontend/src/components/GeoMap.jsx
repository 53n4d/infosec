import { useEffect, useRef, useState, useCallback, useMemo } from 'react'
import { FiX } from 'react-icons/fi'

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

function countryFlag(code) {
  if (!code || code.length !== 2) return '🌐'
  const offset = 0x1F1E6 - 65
  return String.fromCodePoint(code.toUpperCase().charCodeAt(0) + offset) +
         String.fromCodePoint(code.toUpperCase().charCodeAt(1) + offset)
}

function projectLL(lat, lon, w, h, margin = 0) {
  const x = ((lon + 180) / 360) * (w - 2 * margin) + margin
  const y = ((90 - lat) / 180) * (h - 2 * margin) + margin
  return { x, y }
}

function ipJitter(ip) {
  let h = 0
  for (let i = 0; i < ip.length; i++) h = (h * 31 + ip.charCodeAt(i)) >>> 0
  const angle = (h % 360) * (Math.PI / 180)
  const r = 0.5 + ((h >> 10) % 100) / 100 * 1.0
  return { dx: Math.cos(angle) * r, dy: Math.sin(angle) * r }
}

// ─────────────────────────────────────────────────────────────────────────────
// TopoJSON → SVG path converter
// ─────────────────────────────────────────────────────────────────────────────

function decodeArc(arc, transform) {
  const { scale, translate } = transform
  let x = 0, y = 0
  return arc.map(([dx, dy]) => {
    x += dx
    y += dy
    return [x * scale[0] + translate[0], y * scale[1] + translate[1]]
  })
}

function stitchArcs(topology, arcIndices) {
  const coords = []
  for (let idx of arcIndices) {
    const reversed = idx < 0
    const arc = topology.arcs[reversed ? ~idx : idx]
    const decoded = decodeArc(arc, topology.transform)
    const pts = reversed ? decoded.slice().reverse() : decoded
    coords.push(...(coords.length === 0 ? pts : pts.slice(1)))
  }
  return coords
}

function topoGeomToPath(topology, geometry, W, H, MARGIN) {
  const paths = []
  const renderRings = (rings) => {
    let d = ''
    for (const ring of rings) {
      const coords = stitchArcs(topology, ring)
      if (coords.length < 2) continue
      let segment = []
      const segments = [segment]
      for (let i = 0; i < coords.length; i++) {
        if (i > 0) {
          const prevLon = coords[i - 1][0]
          const currLon = coords[i][0]
          if (Math.abs(currLon - prevLon) > 180) {
            segment = []
            segments.push(segment)
          }
        }
        segment.push(coords[i])
      }
      for (let si = 0; si < segments.length; si++) {
        const seg = segments[si]
        if (seg.length < 2) continue
        const pts = seg.map(([lon, lat]) => {
          const { x, y } = projectLL(lat, lon, W, H, MARGIN)
          return `${x.toFixed(1)},${y.toFixed(1)}`
        })
        if (si === 0) {
          d += `M ${pts[0]} L ${pts.slice(1).join(' L ')} Z `
        } else {
          d += `M ${pts[0]} L ${pts.slice(1).join(' L ')} `
        }
      }
    }
    return d.trim()
  }
  if (geometry.type === 'Polygon') {
    const d = renderRings(geometry.arcs)
    if (d) paths.push(d)
  } else if (geometry.type === 'MultiPolygon') {
    for (const polygon of geometry.arcs) {
      const d = renderRings(polygon)
      if (d) paths.push(d)
    }
  }
  return paths
}

function topoToPaths(topology, objectName, W, H, MARGIN) {
  const obj = topology.objects[objectName]
  if (!obj) return []
  const allPaths = []
  for (const geom of obj.geometries) {
    const paths = topoGeomToPath(topology, geom, W, H, MARGIN)
    allPaths.push(...paths)
  }
  return allPaths
}

function computeFitTransform(points, W, H, MARGIN) {
  if (!points.length) return { x: 0, y: 0, k: 1 }
  const lats = points.map(p => p.lat)
  const lons = points.map(p => p.lon)
  const minLat = Math.min(...lats), maxLat = Math.max(...lats)
  const minLon = Math.min(...lons), maxLon = Math.max(...lons)
  const padLat = Math.max((maxLat - minLat) * 0.8, 4)
  const padLon = Math.max((maxLon - minLon) * 0.8, 6)
  const pMinLat = minLat - padLat, pMaxLat = maxLat + padLat
  const pMinLon = minLon - padLon, pMaxLon = maxLon + padLon
  const { x: x1, y: y1 } = projectLL(pMaxLat, pMinLon, W, H, MARGIN)
  const { x: x2, y: y2 } = projectLL(pMinLat, pMaxLon, W, H, MARGIN)
  const bw = Math.max(x2 - x1, 1), bh = Math.max(y2 - y1, 1)
  const k  = Math.min(W / bw, H / bh, 200)
  const cx = (x1 + x2) / 2
  const cy = (y1 + y2) / 2
  return { k, x: W / 2 - cx * k, y: H / 2 - cy * k }
}

// ─────────────────────────────────────────────────────────────────────────────
// Styles — matching the new XSEVERITY design language
// ─────────────────────────────────────────────────────────────────────────────

const CSS = `
  .gm-backdrop {
    position: fixed;
    inset: 0;
    z-index: 1000;
    background: rgba(5, 10, 20, 0.75);
    backdrop-filter: blur(3px);
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .gm-wrap {
    display: flex;
    flex-direction: column;
    width: min(1100px, 95vw);
    height: min(620px, 90vh);
    background: #0a0e1a;
    border: 1px solid #1a2a3a;
    box-shadow: 0 0 0 1px rgba(0,212,255,0.08), 0 32px 80px rgba(0,0,0,0.8);
    font-family: 'JetBrains Mono', 'Fira Mono', monospace;
    overflow: hidden;
    border-radius: 3px;
  }

  /* ── Header ── */
  .gm-header {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 0 14px;
    height: 36px;
    background: #0d1117;
    border-bottom: 1px solid #1a2a3a;
    flex-shrink: 0;
  }

  .gm-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: #00d4ff;
    box-shadow: 0 0 6px #00d4ff;
    flex-shrink: 0;
  }

  .gm-title {
    font-size: 0.65rem;
    font-weight: 700;
    letter-spacing: 0.15em;
    color: #e0eeff;
    text-transform: uppercase;
  }

  .gm-sub {
    font-size: 0.6rem;
    color: #3a5a7a;
    letter-spacing: 0.05em;
  }

  .gm-badges {
    display: flex;
    gap: 6px;
    margin-left: 6px;
    flex-wrap: nowrap;
    overflow: hidden;
  }

  .gm-badge {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 2px 7px;
    border-radius: 2px;
    font-size: 0.58rem;
    letter-spacing: 0.04em;
    background: #0d1f2e;
    border: 1px solid #1a3a50;
    color: #8ab4cc;
    white-space: nowrap;
  }

  .gm-badge b {
    color: #00d4ff;
    font-weight: 700;
  }

  .gm-badge--port {
    border-color: #1a3a28;
    background: #0d1f18;
    color: #7abf99;
  }

  .gm-badge--port b {
    color: #00ff88;
  }

  .gm-close {
    margin-left: auto;
    display: flex;
    align-items: center;
    justify-content: center;
    width: 24px;
    height: 24px;
    border-radius: 2px;
    border: 1px solid #1a2a3a;
    background: transparent;
    color: #3a5a7a;
    cursor: pointer;
    transition: all 0.15s;
    flex-shrink: 0;
  }

  .gm-close:hover {
    border-color: #00d4ff;
    color: #00d4ff;
    background: #001a2a;
  }

  /* ── Body ── */
  .gm-body {
    display: flex;
    flex: 1;
    overflow: hidden;
    min-height: 0;
  }

  /* ── Map ── */
  .gm-map-wrap {
    flex: 1;
    position: relative;
    overflow: hidden;
    background: #050d14;
  }

  .gm-svg {
    width: 100%;
    height: 100%;
    display: block;
  }

  .gm-hint {
    position: absolute;
    bottom: 8px;
    left: 50%;
    transform: translateX(-50%);
    font-size: 0.55rem;
    color: #1e3a50;
    letter-spacing: 0.08em;
    pointer-events: none;
    white-space: nowrap;
  }

  /* ── Tooltip ── */
  .gm-tooltip {
    position: absolute;
    pointer-events: none;
    background: #0d1117;
    border: 1px solid #1a3a50;
    border-radius: 3px;
    padding: 8px 10px;
    min-width: 160px;
    box-shadow: 0 4px 24px rgba(0,0,0,0.7), 0 0 0 1px rgba(0,212,255,0.08);
    z-index: 10;
  }

  .gm-tip-ip {
    font-size: 0.7rem;
    font-weight: 700;
    color: #00d4ff;
    letter-spacing: 0.06em;
    margin-bottom: 6px;
    border-bottom: 1px solid #1a2a3a;
    padding-bottom: 5px;
  }

  .gm-tip-row {
    display: flex;
    align-items: center;
    gap: 6px;
    margin-top: 3px;
    font-size: 0.6rem;
  }

  .gm-tip-label {
    color: #2a4a6a;
    letter-spacing: 0.1em;
    font-size: 0.55rem;
    min-width: 48px;
  }

  .gm-tip-soft {
    margin-left: 4px;
    color: #3a6a5a;
    font-size: 0.58rem;
  }

  .gm-tip-dim {
    color: #6a8aa0;
    font-size: 0.58rem;
  }

  .gm-tip-coords {
    color: #4a6a80;
    font-size: 0.58rem;
    font-variant-numeric: tabular-nums;
  }

  /* ── Sidebar ── */
  .gm-sidebar {
    width: 200px;
    flex-shrink: 0;
    display: flex;
    flex-direction: column;
    border-left: 1px solid #1a2a3a;
    background: #0d1117;
    overflow: hidden;
  }

  .gm-sidebar-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 8px 10px 6px;
    border-bottom: 1px solid #1a2a3a;
    flex-shrink: 0;
  }

  .gm-sidebar-search {
    margin: 6px 8px;
    padding: 4px 8px;
    background: #0a0e1a;
    border: 1px solid #1a2a3a;
    border-radius: 2px;
    color: #8ab4cc;
    font-size: 0.6rem;
    font-family: inherit;
    outline: none;
    transition: border-color 0.15s;
    flex-shrink: 0;
  }

  .gm-sidebar-search::placeholder {
    color: #2a4a6a;
  }

  .gm-sidebar-search:focus {
    border-color: #00d4ff;
  }

  .gm-sidebar-list {
    flex: 1;
    overflow-y: auto;
    overflow-x: hidden;
  }

  .gm-sidebar-list::-webkit-scrollbar {
    width: 3px;
  }
  .gm-sidebar-list::-webkit-scrollbar-track {
    background: transparent;
  }
  .gm-sidebar-list::-webkit-scrollbar-thumb {
    background: #1a3a50;
    border-radius: 2px;
  }

  .gm-sidebar-row {
    padding: 7px 10px;
    cursor: pointer;
    border-bottom: 1px solid #0f1a24;
    transition: background 0.1s;
  }

  .gm-sidebar-row:hover,
  .gm-sidebar-row--hovered {
    background: #0d1f2e;
  }

  .gm-sidebar-row--selected {
    background: #0a1e2e;
    border-left: 2px solid #00d4ff;
    padding-left: 8px;
  }

  .gm-sidebar-row-top {
    display: flex;
    align-items: baseline;
    gap: 4px;
  }

  .gm-sidebar-ip {
    font-size: 0.62rem;
    color: #c0d8e8;
    letter-spacing: 0.04em;
    font-variant-numeric: tabular-nums;
  }

  .gm-sidebar-port {
    font-size: 0.58rem;
    color: #00d4ff;
  }

  .gm-sidebar-meta {
    font-size: 0.58rem;
    color: #3a5a7a;
    margin-top: 2px;
  }

  .gm-sidebar-sw {
    font-size: 0.55rem;
    color: #2a5a4a;
    margin-top: 1px;
  }
`

// ─────────────────────────────────────────────────────────────────────────────
// Component
// ─────────────────────────────────────────────────────────────────────────────

export default function GeoMap({ points = [], onClose }) {
  const W = 960, H = 500, MARGIN = 20
  const svgRef = useRef(null)

  const [landPaths,     setLandPaths]     = useState([])
  const [mapLoading,    setMapLoading]    = useState(true)
  const [tooltip,       setTooltip]       = useState(null)
  const [hovered,       setHovered]       = useState(null)
  const [selected,      setSelected]      = useState(null)
  const [transform,     setTransform]     = useState(() => computeFitTransform(points, W, H, MARGIN))
  const [dragging,      setDragging]      = useState(null)
  const [sidebarFilter, setSidebarFilter] = useState('')

  useEffect(() => {
    const URL = 'https://cdn.jsdelivr.net/npm/world-atlas@2/land-110m.json'
    fetch(URL)
      .then(r => r.json())
      .then(topo => {
        const paths = topoToPaths(topo, 'land', W, H, MARGIN)
        setLandPaths(paths)
      })
      .catch(() => {})
      .finally(() => setMapLoading(false))
  }, [])

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
    Object.entries(countryCounts).sort((a, b) => b[1] - a[1]).slice(0, 5),
    [countryCounts])

  const topPort = useMemo(() => {
    const pc = points.reduce((acc, p) => {
      if (p.port) acc[p.port] = (acc[p.port] || 0) + 1
      return acc
    }, {})
    return Object.entries(pc).sort((a, b) => b[1] - a[1])[0]
  }, [points])

  const filteredPoints = useMemo(() =>
    sidebarFilter
      ? points.filter(p =>
          p.ip.includes(sidebarFilter) ||
          (p.country || '').toLowerCase().includes(sidebarFilter.toLowerCase()) ||
          (p.city    || '').toLowerCase().includes(sidebarFilter.toLowerCase()))
      : points,
    [points, sidebarFilter])

  const handleWheel = useCallback((e) => {
    e.preventDefault()
    const delta = e.deltaY > 0 ? 0.85 : 1.18
    setTransform(t => {
      const newK = Math.max(0.8, Math.min(200, t.k * delta))
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
    const k = Math.min(transform.k * 2.5, 80)
    setTransform({ x: W / 2 - x * k, y: H / 2 - y * k, k })
  }

  // Dot color: cyan for selected, white for hovered, green for default — matching screenshot
  const dotColor = (ip) => {
    if (selected === ip) return '#00d4ff'
    if (hovered  === ip) return '#ffffff'
    return '#00ff88'
  }

  return (
    <>
      <style>{CSS}</style>
      <div className="gm-backdrop" onClick={(e) => { if (e.target === e.currentTarget) onClose?.() }}>
      <div className="gm-wrap">

        {/* ── Header ── */}
        <div className="gm-header">
          <span className="gm-dot" />
          <span className="gm-title">GEO MAP</span>
          <span className="gm-sub">
            {points.length} host{points.length !== 1 ? 's' : ''} ·{' '}
            {Object.keys(countryCounts).length} countr{Object.keys(countryCounts).length !== 1 ? 'ies' : 'y'}
          </span>

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

          {onClose && (
            <button className="gm-close" onClick={onClose} title="Close (ESC)">
              <FiX size={13} />
            </button>
          )}
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
                  <feGaussianBlur stdDeviation="2" result="blur" />
                  <feMerge>
                    <feMergeNode in="blur" />
                    <feMergeNode in="SourceGraphic" />
                  </feMerge>
                </filter>
              </defs>

              <g transform={`translate(${transform.x},${transform.y}) scale(${transform.k})`}>

                {/* Ocean */}
                <rect x={0} y={0} width={W} height={H} fill="url(#gm-ocean)" />

                {/* Grid */}
                {[...Array(13)].map((_, i) => (
                  <line key={`gv${i}`}
                    x1={(i / 12) * W} y1={0} x2={(i / 12) * W} y2={H}
                    stroke="#0e2a40" strokeWidth="0.4" strokeOpacity="0.5" />
                ))}
                {[...Array(7)].map((_, i) => (
                  <line key={`gh${i}`}
                    x1={0} y1={(i / 6) * H} x2={W} y2={(i / 6) * H}
                    stroke="#0e2a40" strokeWidth="0.4" strokeOpacity="0.5" />
                ))}

                {/* Latitude labels */}
                {[80, 60, 40, 20, 0, -20, -40, -60].map(lat => {
                  const { y } = projectLL(lat, -175, W, H, MARGIN)
                  return (
                    <text key={lat} x={MARGIN + 2} y={y - 2}
                      fontSize="7" fill="#1a3a55" fontFamily="monospace">
                      {lat}°
                    </text>
                  )
                })}

                {/* Loading */}
                {mapLoading && (
                  <text x={W / 2} y={H / 2} textAnchor="middle"
                    fontSize="11" fill="#1a3a55" fontFamily="monospace">
                    loading map…
                  </text>
                )}

                {/* Land — slightly brighter fill to match screenshot's visible landmasses */}
                {landPaths.map((d, i) => (
                  <path key={i} d={d}
                    fill="#0e2438"
                    stroke="#1a3a55"
                    strokeWidth="0.6"
                    strokeLinejoin="round"
                  />
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
                      fill="#00d4ff" fillOpacity="0.45"
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
                  const color = dotColor(p.ip)
                  const baseR  = (isHov || isSel ? 5.5 : 3.5) / transform.k
                  const ringR  = 10 / transform.k
                  const ringR2 = 16 / transform.k
                  const sw     = 1  / transform.k
                  return (
                    <g key={p.ip}
                      style={{ cursor: 'pointer' }}
                      onMouseEnter={(e) => {
                        setHovered(p.ip)
                        const rect = svgRef.current.getBoundingClientRect()
                        setTooltip({ x: e.clientX - rect.left, y: e.clientY - rect.top, point: p })
                      }}
                      onMouseLeave={() => { setHovered(null); setTooltip(null) }}
                      onClick={() => setSelected(p.ip === selected ? null : p.ip)}
                    >
                      {transform.k > 2 && <>
                        <circle cx={x} cy={y} r={ringR}
                          fill="none" stroke={color} strokeWidth={sw}
                          strokeOpacity="0.35" />
                        <circle cx={x} cy={y} r={ringR2}
                          fill="none" stroke={color} strokeWidth={sw * 0.5}
                          strokeOpacity="0.15" />
                      </>}
                      <circle cx={x} cy={y}
                        r={baseR}
                        fill={color}
                        fillOpacity={isHov || isSel ? 1 : 0.85}
                        filter={isHov || isSel ? 'url(#gm-glow)' : undefined}
                        style={{ transition: 'r 0.1s' }} />
                    </g>
                  )
                })}
              </g>
            </svg>

            {/* Tooltip */}
            {tooltip && (
              <div className="gm-tooltip" style={{
                left: Math.min(tooltip.x + 14, 680),
                top:  Math.max(tooltip.y - 10, 10),
              }}>
                <div className="gm-tip-ip">{tooltip.point.ip}</div>
                {tooltip.point.port && (
                  <div className="gm-tip-row">
                    <span className="gm-tip-label">PORT</span>
                    <span style={{ color: '#00d4ff' }}>{tooltip.point.port}</span>
                    {tooltip.point.software && (
                      <span className="gm-tip-soft">{tooltip.point.software}</span>
                    )}
                  </div>
                )}
                <div className="gm-tip-row">
                  <span className="gm-tip-label">COUNTRY</span>
                  <span style={{ color: '#8ab4cc' }}>{countryFlag(tooltip.point.countryCode)} {tooltip.point.country || '—'}</span>
                </div>
                {tooltip.point.city && (
                  <div className="gm-tip-row">
                    <span className="gm-tip-label">CITY</span>
                    <span style={{ color: '#8ab4cc' }}>{tooltip.point.city}</span>
                  </div>
                )}
                {tooltip.point.isp && (
                  <div className="gm-tip-row">
                    <span className="gm-tip-label">ISP</span>
                    <span className="gm-tip-dim">{tooltip.point.isp}</span>
                  </div>
                )}
                {tooltip.point.org && tooltip.point.org !== tooltip.point.isp && (
                  <div className="gm-tip-row">
                    <span className="gm-tip-label">ORG</span>
                    <span className="gm-tip-dim">{tooltip.point.org}</span>
                  </div>
                )}
                <div className="gm-tip-row">
                  <span className="gm-tip-label">LAT/LON</span>
                  <span className="gm-tip-coords">
                    {tooltip.point.lat?.toFixed(3)}, {tooltip.point.lon?.toFixed(3)}
                  </span>
                </div>
              </div>
            )}

            <p className="gm-hint">scroll to zoom · drag to pan · click pin to highlight</p>
          </div>

          {/* Sidebar */}
          <div className="gm-sidebar">
            <div className="gm-sidebar-head">
              <span style={{ fontSize: '0.6rem', color: '#00d4ff', letterSpacing: '0.12em', fontFamily: 'monospace' }}>HOSTS</span>
              <span style={{ fontSize: '0.6rem', color: '#2a4a6a', fontFamily: 'monospace' }}>{points.length}</span>
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
                  ].join(' ')}
                  onClick={() => flyTo(p)}
                  onMouseEnter={() => setHovered(p.ip)}
                  onMouseLeave={() => setHovered(null)}
                >
                  <div className="gm-sidebar-row-top">
                    <span className="gm-sidebar-ip">{p.ip}</span>
                    {p.port && <span className="gm-sidebar-port">:{p.port}</span>}
                  </div>
                  <div className="gm-sidebar-meta">
                    {countryFlag(p.countryCode)} {p.city ? `${p.city}, ` : ''}{p.country || '—'}
                  </div>
                  {p.software && <div className="gm-sidebar-sw">{p.software}</div>}
                </div>
              ))}
              {filteredPoints.length === 0 && (
                <p style={{ padding: '12px', color: '#2a4a6a', fontSize: '0.65rem', fontFamily: 'monospace' }}>
                  no matches
                </p>
              )}
            </div>
          </div>

        </div>
      </div>
      </div>
    </>
  )
}