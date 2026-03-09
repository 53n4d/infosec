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

// Equirectangular projection — maps [lon, lat] → [x, y] in viewBox space
function projectLL(lat, lon, w, h, margin = 0) {
  const x = ((lon + 180) / 360) * (w - 2 * margin) + margin
  const y = ((90 - lat) / 180) * (h - 2 * margin) + margin
  return { x, y }
}

function ipJitter(ip) {
  let h = 0
  for (let i = 0; i < ip.length; i++) h = (h * 31 + ip.charCodeAt(i)) >>> 0
  const angle = (h % 360) * (Math.PI / 180)
  // Use 1.5° spread radius so IPs in the same city are visually separated at high zoom
  const r = 0.5 + ((h >> 10) % 100) / 100 * 1.0   // 0.5° – 1.5°
  return { dx: Math.cos(angle) * r, dy: Math.sin(angle) * r }
}

// ─────────────────────────────────────────────────────────────────────────────
// TopoJSON → SVG path converter (no d3 required)
// ─────────────────────────────────────────────────────────────────────────────

// Decode TopoJSON delta-encoded arc into [lon, lat] coordinate array
function decodeArc(arc, transform) {
  const { scale, translate } = transform
  let x = 0, y = 0
  return arc.map(([dx, dy]) => {
    x += dx
    y += dy
    return [x * scale[0] + translate[0], y * scale[1] + translate[1]]
  })
}

// Stitch TopoJSON arcs into a single coordinate ring, respecting arc reversal
function stitchArcs(topology, arcIndices) {
  const coords = []
  for (let idx of arcIndices) {
    const reversed = idx < 0
    const arc = topology.arcs[reversed ? ~idx : idx]
    const decoded = decodeArc(arc, topology.transform)
    const pts = reversed ? decoded.slice().reverse() : decoded
    // Skip first point of each arc except the first (it's shared with previous arc's last)
    coords.push(...(coords.length === 0 ? pts : pts.slice(1)))
  }
  return coords
}

// Convert a TopoJSON geometry object into SVG path strings, splitting on antimeridian crossings
function topoGeomToPath(topology, geometry, W, H, MARGIN) {
  const paths = []

  const renderRings = (rings) => {
    let d = ''
    for (const ring of rings) {
      const coords = stitchArcs(topology, ring)
      if (coords.length < 2) continue

      // Split ring into sub-segments at antimeridian crossings (lon jump > 180°)
      // This prevents lines shooting across the entire map for Russia, Antarctica etc.
      let segment = []
      const segments = [segment]
      for (let i = 0; i < coords.length; i++) {
        if (i > 0) {
          const prevLon = coords[i - 1][0]
          const currLon = coords[i][0]
          if (Math.abs(currLon - prevLon) > 180) {
            // Antimeridian crossing — start a new sub-segment (MoveTo instead of LineTo)
            segment = []
            segments.push(segment)
          }
        }
        segment.push(coords[i])
      }

      // Render each sub-segment as its own M...L...Z (or just M...L if it's a continuation)
      for (let si = 0; si < segments.length; si++) {
        const seg = segments[si]
        if (seg.length < 2) continue
        const pts = seg.map(([lon, lat]) => {
          const { x, y } = projectLL(lat, lon, W, H, MARGIN)
          return `${x.toFixed(1)},${y.toFixed(1)}`
        })
        // First segment gets M+Z (closes back), subsequent segments are open sub-paths
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

// Main converter: returns array of SVG path `d` strings from a TopoJSON object name
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

// ─────────────────────────────────────────────────────────────────────────────
// Compute initial transform to fit all points in view
// ─────────────────────────────────────────────────────────────────────────────
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
  // Lazy initial state — compute fit transform once from points at mount
  const [transform,     setTransform]     = useState(() => computeFitTransform(points, W, H, MARGIN))
  const [dragging,      setDragging]      = useState(null)
  const [sidebarFilter, setSidebarFilter] = useState('')


  // ── Load real world map data ──────────────────────────────────────────────
  useEffect(() => {
    // Natural Earth 110m land polygons via TopoJSON — lightweight (~105KB), public domain
    const URL = 'https://cdn.jsdelivr.net/npm/world-atlas@2/land-110m.json'
    fetch(URL)
      .then(r => r.json())
      .then(topo => {
        // world-atlas uses object name "land"
        const paths = topoToPaths(topo, 'land', W, H, MARGIN)
        setLandPaths(paths)
      })
      .catch(() => {
        // Silent fallback — dots still render, just no land background
      })
      .finally(() => setMapLoading(false))
  }, [])

  // ── ESC to close ─────────────────────────────────────────────────────────
  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') onClose?.() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  // ── Derived stats ─────────────────────────────────────────────────────────
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

  // ── Zoom ──────────────────────────────────────────────────────────────────
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
    const k = Math.min(transform.k * 2.5, 80)   // zoom in further but don't exceed 80×
    setTransform({ x: W / 2 - x * k, y: H / 2 - y * k, k })
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Render
  // ─────────────────────────────────────────────────────────────────────────
  return (
    <div className="gm-backdrop" onClick={(e) => { if (e.target === e.currentTarget) onClose?.() }}>
      <div className="gm-modal">

        {/* ── Header ── */}
        <div className="gm-header">
          <div className="gm-header-left">
            <span className="gm-dot" />
            <span className="gm-title mono">GEO MAP</span>
            <span className="gm-sub mono">
              {points.length} host{points.length !== 1 ? 's' : ''} ·{' '}
              {Object.keys(countryCounts).length} countr{Object.keys(countryCounts).length !== 1 ? 'ies' : 'y'}
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

                {/* Ocean background */}
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

                {/* Real landmasses from Natural Earth TopoJSON */}
                {mapLoading && (
                  <text x={W / 2} y={H / 2} textAnchor="middle"
                    fontSize="11" fill="#1e4060" fontFamily="monospace">
                    loading map…
                  </text>
                )}
                {landPaths.map((d, i) => (
                  <path key={i} d={d}
                    fill="#0e2035"
                    stroke="#1e4060"
                    strokeWidth="0.5"
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
                      fill="var(--accent)" fillOpacity="0.55"
                      fontFamily="monospace"
                      style={{ pointerEvents: 'none' }}>
                      {country} ×{pts.length}
                    </text>
                  )
                })}

                {/* Host dots — radius divided by k so they're constant pixel-size at any zoom */}
                {points.map((p) => {
                  const j = ipJitter(p.ip)
                  const { x, y } = projectLL(p.lat + j.dy, p.lon + j.dx, W, H, MARGIN)
                  const isHov = hovered  === p.ip
                  const isSel = selected === p.ip
                  const color = isSel ? '#ffdd00' : isHov ? '#ffffff' : '#00ff88'
                  // Scale dot radius inversely so it's always ~4–6px on screen
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
                      {/* Pulse rings — only show when not too zoomed out (they'd overlap) */}
                      {transform.k > 2 && <>
                        <circle cx={x} cy={y} r={ringR}
                          fill="none" stroke={color} strokeWidth={sw}
                          strokeOpacity="0.4"
                          style={{ animation: 'none', opacity: 0.4 }} />
                        <circle cx={x} cy={y} r={ringR2}
                          fill="none" stroke={color} strokeWidth={sw * 0.5}
                          strokeOpacity="0.2" />
                      </>}
                      <circle cx={x} cy={y}
                        r={baseR}
                        fill={color}
                        fillOpacity={isHov || isSel ? 1 : 0.9}
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
                    <span style={{ color: 'var(--accent)' }}>{tooltip.point.port}</span>
                    {tooltip.point.software && (
                      <span className="gm-tip-soft">{tooltip.point.software}</span>
                    )}
                  </div>
                )}
                <div className="gm-tip-row">
                  <span className="gm-tip-label">COUNTRY</span>
                  <span>{countryFlag(tooltip.point.countryCode)} {tooltip.point.country || '—'}</span>
                </div>
                {tooltip.point.city && (
                  <div className="gm-tip-row">
                    <span className="gm-tip-label">CITY</span>
                    <span>{tooltip.point.city}</span>
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

            <p className="gm-hint mono">scroll to zoom · drag to pan · click pin to highlight</p>
          </div>

          {/* Sidebar */}
          <div className="gm-sidebar">
            <div className="gm-sidebar-head">
              <span className="mono" style={{ fontSize: '0.7rem', color: 'var(--accent)', letterSpacing: 2 }}>HOSTS</span>
              <span className="mono" style={{ fontSize: '0.7rem', color: 'var(--dim)' }}>{points.length}</span>
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