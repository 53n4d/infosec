import { useState, useEffect, useRef, useCallback, useMemo } from 'react'
import { useLocation, useNavigate, useParams } from 'react-router-dom'
import {
  FiAlertTriangle,
  FiArrowUpRight,
  FiDownload,
  FiFilter,
  FiGlobe,
  FiLock,
  FiPlay,
  FiRefreshCw,
  FiSearch,
  FiShare2,
  FiZap,
} from 'react-icons/fi'
import { startScan, streamScanJob, fetchCountries, fetchIpInfo } from '../api'
import { contributeCountryIntel } from '../intel'

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

function severityColor(score) {
  const n = parseFloat(score)
  if (isNaN(n)) return 'var(--dim)'
  if (n >= 9.0) return 'var(--crit)'
  if (n >= 7.0) return 'var(--high)'
  if (n >= 4.0) return 'var(--med)'
  return 'var(--low)'
}

function GeoMap({ points }) {
  const width = 960
  const height = 520
  const margin = 36

  const jitter = (ip) => {
    let h = 0
    for (let i = 0; i < ip.length; i++) h = (h * 31 + ip.charCodeAt(i)) >>> 0
    const angle = (h % 360) * (Math.PI / 180)
    const r = 0.25 + ((h >> 10) % 20) / 100 // 0.25°–0.45°
    return { dx: Math.cos(angle) * r, dy: Math.sin(angle) * r }
  }

  // Bounding box with padding
  const lats = points.map(p => p.lat)
  const lons = points.map(p => p.lon)
  const minLat = Math.min(...lats, -85)
  const maxLat = Math.max(...lats, 85)
  const minLon = Math.min(...lons, -179)
  const maxLon = Math.max(...lons, 179)
  const latSpan = Math.max(10, maxLat - minLat)
  const lonSpan = Math.max(10, maxLon - minLon)

  const project = (lat, lon) => {
    const x = ((lon - minLon) / lonSpan) * (width - 2 * margin) + margin
    const y = ((maxLat - lat) / latSpan) * (height - 2 * margin) + margin
    return { x, y }
  }

  return (
    <div className="geo-map">
      <svg viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Discovered hosts map">
        <defs>
          <linearGradient id="geo-bg" x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor="rgba(0,255,136,0.10)" />
            <stop offset="100%" stopColor="rgba(0,0,0,0.65)" />
          </linearGradient>
          <radialGradient id="geo-dot" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="var(--accent)" stopOpacity="1" />
            <stop offset="100%" stopColor="var(--accent)" stopOpacity="0.2" />
          </radialGradient>
        </defs>
        <rect x="0" y="0" width={width} height={height} fill="url(#geo-bg)" stroke="var(--border2)" />

        {/* Graticule */}
        {[...Array(7)].map((_, i) => {
          const y = margin + (i / 6) * (height - 2 * margin)
          return <line key={`g-h-${i}`} x1={margin} y1={y} x2={width - margin} y2={y} stroke="var(--border2)" strokeOpacity="0.25" strokeWidth="0.5" />
        })}
        {[...Array(7)].map((_, i) => {
          const x = margin + (i / 6) * (width - 2 * margin)
          return <line key={`g-v-${i}`} y1={margin} x1={x} y2={height - margin} x2={x} stroke="var(--border2)" strokeOpacity="0.25" strokeWidth="0.5" />
        })}

        {points.map((p) => {
          const j = jitter(p.ip)
          const { x, y } = project(p.lat + j.dy, p.lon + j.dx)
          return (
            <g key={p.ip}>
              <circle cx={x} cy={y} r={7} fill="url(#geo-dot)" />
              <text x={x + 10} y={y + 4} fontSize="11" fill="var(--text)" opacity="0.9">
                {p.country || p.ip}
              </text>
            </g>
          )
        })}
      </svg>
      <div className="geo-map-meta">
        <span>{points.length} host{points.length !== 1 ? 's' : ''} geolocated · {new Set(points.map(p => p.country || 'Unknown')).size} countries</span>
      </div>
    </div>
  )
}

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
      (c) => c.code.toLowerCase().includes(term) || c.name.toLowerCase().includes(term)
    )
  }, [countries, countryInput])

  const commitCountry = (code, name) => {
    const found = name ? { code, name } : countries.find((c) => c.code === code)
    setCountry(code)
    setCountryName(found?.name || code)
    setCountryInput(found ? `${found.code} - ${found.name}` : code)
    setPickerOpen(false)
  }

  useEffect(() => {
    fetchCountries()
      .then((data) => {
        setCountries(data)
        // Only set default country if:
        // - not coming from navigation state (RangeLookup)
        // - not reconnecting to an existing job (urlJobId)
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

// ── Hit filter + selection ────────────────────────────────────────────
const [onlyFindings,       setOnlyFindings]       = useState(true)
const [portServiceFilter,  setPortServiceFilter]  = useState('')
const [severityFilter,     setSeverityFilter]     = useState('all') // all | high | critical
const [selectedIPs,        setSelectedIPs]        = useState(new Set())
const [geoPoints,          setGeoPoints]          = useState([])
const [geoLoading,         setGeoLoading]         = useState(false)
const [geoError,           setGeoError]           = useState('')

const hitMaxScore = (hit) => {
  if (!hit.cves?.length) return 0
  return Math.max(...hit.cves.map(c => parseFloat(c.score || '0') || 0))
}

const matchesPortService = (hit, term) => {
  const t = term.trim().toLowerCase()
  if (!t) return true
  const portNum = Number(t)
  if (!Number.isNaN(portNum)) return hit.port === portNum
  return (
    (hit.software && hit.software.toLowerCase().includes(t)) ||
    (hit.banner && hit.banner.toLowerCase().includes(t))
  )
}

const passesSeverity = (hit) => {
  if (severityFilter === 'all') return true
  const maxScore = hitMaxScore(hit)
  if (severityFilter === 'critical') return maxScore >= 9.0
  if (severityFilter === 'high') return maxScore >= 7.0
  return true
}

const visibleHits = useMemo(() => {
  const base = onlyFindings ? hits.filter(h => h.status !== 'silent' && h.port > 0) : hits
  return base.filter((hit) => matchesPortService(hit, portServiceFilter)).filter(passesSeverity)
}, [hits, onlyFindings, portServiceFilter, severityFilter])

  const toggleSelectIP = (ip) => {
    setSelectedIPs(prev => {
      const next = new Set(prev)
      if (next.has(ip)) next.delete(ip)
      else next.add(ip)
      return next
    })
  }

  const visibleUniqueIPs = useMemo(() => [...new Set(visibleHits.map(h => h.ip))], [visibleHits])
  const selectAllVisible = () => setSelectedIPs(new Set(visibleUniqueIPs))
  const clearSelection   = () => setSelectedIPs(new Set())

const rescanSelected = () => {
  if (selectedIPs.size === 0) return
  const newRanges = Array.from(selectedIPs).join('\n')
  navigate('/scan/new', {
    state: { ranges: newRanges, country, countryName }
  })
}

const exportResults = (format) => {
  const rows = visibleHits.map((h) => ({
    ip: h.ip,
    port: h.port,
    status: h.status,
    software: h.software || '',
    banner: h.banner || '',
    cve_count: h.cves?.length || 0,
    max_cvss: hitMaxScore(h),
    range: h.range || '',
  }))
  if (format === 'json') {
    const blob = new Blob([JSON.stringify(rows, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `scan-${jobId || 'results'}.json`
    a.click()
    URL.revokeObjectURL(url)
    return
  }
  const header = ['ip', 'port', 'status', 'software', 'banner', 'cve_count', 'max_cvss', 'range']
  const csv = [header.join(',')]
  rows.forEach((r) => {
    const vals = header.map((k) => `"${String(r[k]).replace(/\"/g, '""')}"`)
    csv.push(vals.join(','))
  })
  const blob = new Blob([csv.join('\n')], { type: 'text/csv' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `scan-${jobId || 'results'}.csv`
  a.click()
  URL.revokeObjectURL(url)
}

const buildGeoMap = async () => {
  const uniqueIps = [...new Set(visibleHits.map((h) => h.ip))].slice(0, 200)
  setGeoLoading(true)
  setGeoError('')
  const points = []
  for (const ip of uniqueIps) {
    try {
      const info = await fetchIpInfo(ip)
      if (info?.lat != null && info?.lon != null) {
        points.push({ ip, lat: info.lat, lon: info.lon, country: info.country })
      }
    } catch (e) {
      setGeoError(e.message)
      break
    }
  }
  setGeoPoints(points)
  setGeoLoading(false)
}

  const esRef  = useRef(null)
  const logRef = useRef(null)

  // ── Populate from RangeLookup / rescan navigation state ──────────────
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
      setStats({ probed: 0, responsive: intelHits.length, vuln_hosts: intelHits.filter(h => h.cves?.length > 0).length })
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
        setCountryInput(saved.countryName ? `${saved.country} - ${saved.countryName}` : saved.country)
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

  // ── Close port dropdown on outside click ─────────────────────────────
  useEffect(() => {
    const handler = (e) => {
      if (portDropRef.current && !portDropRef.current.contains(e.target)) setPortDropOpen(false)
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight
  }, [hits])

  useEffect(() => () => esRef.current?.close(), [])

  const filteredPortList = useMemo(() => {
    const term = portSearch.toLowerCase().trim()
    if (!term) return ALL_PORTS
    return ALL_PORTS.filter(p => p.port.toString().includes(term) || p.label.toLowerCase().includes(term))
  }, [portSearch])

  const toggleCustomPort = (port) =>
    setCustomPorts(prev => prev.includes(port) ? prev.filter(p => p !== port) : [...prev, port].sort((a, b) => a - b))

  const removeCustomPort = (port) => setCustomPorts(prev => prev.filter(p => p !== port))

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

  const finalPorts = () => {
    if (portMode === 'all')    return []
    if (portMode === 'preset') return PRESET_PORTS
    return customPorts
  }

  // ── Contribute to Firestore ───────────────────────────────────────────
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
      }).then(() => console.log('[intel] ✓ contributed:', countryCode))
        .catch(e => console.warn('[intel] failed:', e.message))
    } catch (e) {
      console.warn('[intel] error:', e.message)
    }
  }

  // ── Start scan ────────────────────────────────────────────────────────
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
        jobId:            job_id,
        country:          country,
        countryName:      countryName,
        ranges:           rangeList,
        rangesText:       ranges,
        startedAt:        Date.now(),
        status:           'running',
        probed:           0,
        open:             0,
        vulns:            0,
        scan_mode:        scanMode,
        nmap_parallelism: nmapParallelism,
        masscan_rate:     masscanRate,
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

  return (
    <div className="scan-shell">
      <aside className="scan-config">
        <div className="scan-config-header">
          <button className="back-link" onClick={() => navigate('/scan')}>← Scan Console</button>
          <p className="mono">{scanMode === 'deep' ? 'deep → os → vuln → firestore' : 'wide → banner → nvd → firestore'}</p>
          <h2>Scan {urlJobId ? urlJobId.slice(0, 8) + '…' : 'New'}</h2>
        </div>

        <form className="form" onSubmit={handleStart}>

          {/* ── Country ── */}
          <div className="field">
            <label>Country <span style={{ color: 'var(--dim)', fontWeight: 400, marginLeft: 6 }}>(intel contribution)</span></label>
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
              <p className="hint mono" style={{ color: 'var(--accent)', fontSize: '0.72rem', marginTop: 4, display: 'inline-flex', alignItems: 'center', gap: 5 }}>
                <FiShare2 size={11} /> results will be contributed to community intel for {country}
              </p>
            )}
          </div>

          {/* ── Ranges ── */}
          <div className="field">
            <label>Target ranges (CIDR, one per line)</label>
            <textarea rows={5} value={ranges} onChange={e => setRanges(e.target.value)}
              placeholder={"192.168.1.0/24\n10.0.0.0/8"} spellCheck={false} />
            <p className="hint">
              {ranges.trim()
                ? `${ranges.trim().split(/\n/).filter(Boolean).length} range(s) loaded`
                : 'Paste CIDRs or use Range Pull to populate'}
            </p>
          </div>

          {/* ── Scan mode ── */}
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

          {/* ── Port mode ── */}
          <div className="field">
            <label>Port mode</label>
            <div className="pill-row">
              {[{ id: 'preset', label: 'CVE Preset' }, { id: 'custom', label: 'Custom' }, { id: 'all', label: 'All Ports' }].map(m => (
                <button key={m.id} type="button"
                  className={portMode === m.id ? 'pill selected' : 'pill'}
                  onClick={() => setPortMode(m.id)}>{m.label}</button>
              ))}
            </div>
            {portMode === 'preset' && (
              <p className="hint mono" style={{ fontSize: '0.7rem', marginTop: 6, lineHeight: 1.6 }}>{PRESET_PORTS.join(', ')}</p>
            )}
            {portMode === 'all' && (
              <p className="hint" style={{ marginTop: 6, display: 'inline-flex', alignItems: 'center', gap: 5 }}>
                <FiAlertTriangle size={12} /> 1–65535 — requires wide scan mode
              </p>
            )}
            {portMode === 'custom' && (
              <div className="port-picker" ref={portDropRef}>
                <div className="port-tags">
                  {customPorts.length === 0 && <span className="hint" style={{ padding: '4px 2px' }}>No ports selected yet</span>}
                  {customPorts.map(p => {
                    const info = ALL_PORTS.find(x => x.port === p)
                    return (
                      <span key={p} className="port-tag">
                        <span className="mono">{p}</span>
                        {info && <span className="port-tag-label">{info.label}</span>}
                        <button type="button" className="port-tag-remove" onClick={() => removeCustomPort(p)}>×</button>
                      </span>
                    )
                  })}
                </div>
                <div className="port-search-wrap">
                  <input value={portSearch}
                    onChange={e => { setPortSearch(e.target.value); setPortDropOpen(true) }}
                    onFocus={() => setPortDropOpen(true)}
                    onKeyDown={handlePortSearchKey}
                    placeholder="Search port or service… (Enter to add)"
                    autoComplete="off" />
                  {customPorts.length > 0 && (
                    <button type="button" className="ghost small" onClick={() => setCustomPorts([])}>Clear</button>
                  )}
                </div>
                {portDropOpen && (
                  <div className="port-drop">
                    {filteredPortList.length === 0 && <div className="port-drop-empty">No matches — press Enter to add {portSearch}</div>}
                    {filteredPortList.map(p => (
                      <button key={p.port} type="button"
                        className={`port-drop-item ${customPorts.includes(p.port) ? 'selected' : ''}`}
                        onMouseDown={e => e.preventDefault()}
                        onClick={() => toggleCustomPort(p.port)}>
                        <span className="mono port-num">{p.port}</span>
                        <span className="port-svc">{p.label}</span>
                        {customPorts.includes(p.port) && <span className="port-check">✓</span>}
                      </button>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>

          {/* ── Rate / Parallelism ── */}
          <div className="field">
            {scanMode === 'wide' ? (
              <>
                <label>Rate (pps) <span className="hint" style={{ marginLeft: 4 }}>max 100,000</span></label>
                <input type="number" value={masscanRate} min={100} max={100000}
                  onChange={e => setMasscanRate(Math.min(100000, Math.max(100, Number(e.target.value))))} />
                {masscanRate > 5000 && (
                  <p className="hint" style={{ color: 'var(--high)', marginTop: 4, display: 'inline-flex', alignItems: 'center', gap: 5 }}>
                    <FiAlertTriangle size={12} /> High rate may miss hosts. Recommended: 500–2000 pps.
                  </p>
                )}
              </>
            ) : (
              <>
                <label>Parallelism <span className="hint" style={{ marginLeft: 4 }}>max 500</span></label>
                <input type="number" value={nmapParallelism} min={1} max={500}
                  onChange={e => setNmapParallelism(Math.min(500, Math.max(1, Number(e.target.value))))} />
                {nmapParallelism > 200 && (
                  <p className="hint" style={{ color: 'var(--high)', marginTop: 4, display: 'inline-flex', alignItems: 'center', gap: 5 }}>
                    <FiAlertTriangle size={12} /> High parallelism may trigger IDS/IPS or drop results.
                  </p>
                )}
              </>
            )}
          </div>

          {/* ── CVE toggle ── */}
          <div className="switch-row">
            <label>
              <input type="checkbox" checked={runCve} onChange={e => setRunCve(e.target.checked)} />
              NVD CVE lookup per banner
            </label>
          </div>

          <div className="scan-actions">
            <button type="submit" className="primary" disabled={jobStatus === 'running'}
              style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
              {jobStatus === 'running'
                ? <><FiRefreshCw size={14} className="spin" /> Scanning...</>
                : <><FiPlay size={14} /> Start Scan</>}
            </button>
            {jobStatus === 'running' && (
              <button type="button" className="ghost" onClick={handleStop}>■ Stop</button>
            )}
          </div>
        </form>

        {/* ── Stats ── */}
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

        {jobId && <p className="hint mono" style={{ marginTop: 8, wordBreak: 'break-all' }}>job: {jobId}</p>}
        {jobStatus && !['running', 'intel'].includes(jobStatus) && (
          <p className={`scan-status-badge ${jobStatus}`}>{jobStatus.toUpperCase()}</p>
        )}
        {error && <p className="error">{error}</p>}
      </aside>

      {/* ── Hit stream ── */}
      <div className="scan-main">
        {intelBanner && (
          <div className="intel-scan-banner">
            <FiZap size={13} style={{ color: 'var(--accent)', marginRight: 6 }} />
            Community data for {intelBanner.country}
            {intelBanner.age_days > 0 ? ` — scanned ${intelBanner.age_days}d ago` : ' — fresh'}
            <button className="ghost small" style={{ marginLeft: 16, fontSize: '0.75rem' }}
              onClick={() => { setIntelBanner(null); setHits([]); setStats({ probed: 0, responsive: 0, vuln_hosts: 0 }); setJobStatus(null) }}>
              Clear — run fresh scan
            </button>
          </div>
        )}

        {/* ── Toolbar ── */}
        {hits.length > 0 && (
          <div className="hit-toolbar">
            <div className="hit-filter-fields">
              <label className="hit-filter-input">
                <FiFilter size={14} />
                <input
                  value={portServiceFilter}
                  onChange={(e) => setPortServiceFilter(e.target.value)}
                  placeholder="Filter by port or service (e.g. 443, redis)"
                />
              </label>
              <label className="hit-filter-select">
                Severity
                <select value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}>
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

            <button className="ghost small" onClick={buildGeoMap} disabled={geoLoading}>
              <FiGlobe size={13} /> {geoLoading ? 'Mapping…' : 'Geo map'}
            </button>
          </div>
        )}

        {geoPoints.length > 0 && (
          <div className="geo-map-wrap">
            <GeoMap points={geoPoints} />
          </div>
        )}
        {geoError && <p className="error" style={{ margin: '8px 16px' }}>{geoError}</p>}

        <div className="hit-stream" ref={logRef}>
          {hits.length === 0 && (
            <div className="hit-empty">
              {jobStatus === 'running'
                ? <><span className="pulse-dot" /> waiting for open ports...</>
                : 'No hits yet. Configure and start a scan, or load community intel from the dashboard.'}
            </div>
          )}

          {/* ── Grouped by IP ── */}
          {(() => {
            const grouped = []
            const ipMap = new Map()
            for (const hit of visibleHits) {
              if (!ipMap.has(hit.ip)) {
                const entry = { ip: hit.ip, ports: [] }
                ipMap.set(hit.ip, entry)
                grouped.push(entry)
              }
              ipMap.get(hit.ip).ports.push(hit)
            }

            return grouped.map(group => {
              const ip          = group.ip
              const allPorts    = group.ports
              const isSilent    = allPorts.length === 1 && allPorts[0].status === 'silent'
              const ports       = isSilent ? [] : allPorts.filter(p => p.port > 0)
              const isSelected  = selectedIPs.has(ip)
              const isActive    = activeHit === ip
              const allCves     = ports.flatMap(p => p.cves || [])
              const hasBanner   = ports.some(p => p.banner || p.software)
              const topCveScore = allCves.length > 0
                ? Math.max(...allCves.map(c => parseFloat(c.score) || 0))
                : null

              return (
                <div key={ip}
                  className={`hit-row ${isActive ? 'active' : ''} ${allCves.length ? 'has-cve' : ''} ${isSelected ? 'selected' : ''}`}
                  onClick={() => setActiveHit(isActive ? null : ip)}>

                  <div className="hit-main-line">
                    <input type="checkbox" className="hit-checkbox"
                      checked={isSelected}
                      onChange={() => toggleSelectIP(ip)}
                      onClick={e => e.stopPropagation()} />
                    <span className={`status-dot ${isSilent ? 'silent' : hasBanner ? 'open' : 'dim'}`} />
                    <span className="mono hit-ip">{ip}</span>

                    <span className="port-chip-row">
                      {isSilent
                        ? <span className="hint" style={{ fontSize: '0.72rem', marginLeft: 4 }}>no response</span>
                        : ports.map((p, pi) => {
                            const hasData = !!(p.banner || p.software || p.cves?.length)
                            return (
                              <span key={pi}
                                className={`port-chip ${hasData ? 'port-chip-hit' : ''}`}
                                title={p.software || (p.banner ? p.banner.slice(0, 80) : 'no banner')}>
                                {p.port}
                                {p.software && <span className="port-chip-svc">{p.software.split(' ')[0]}</span>}
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
                            {!p.banner && !p.software && <span className="hint" style={{ fontSize: '0.72rem' }}>no banner</span>}
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
                                    <span className="score-pill" style={{ color: severityColor(cve.score) }}>
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
                        onClick={e => { e.stopPropagation(); navigate('/ip/' + encodeURIComponent(ip), { state: { hit: ports[0] } }) }}
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
