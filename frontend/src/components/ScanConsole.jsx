import React, { useState, useEffect, useRef, useMemo } from 'react'
import { useLocation, useNavigate, useParams } from 'react-router-dom'
import {
  TbAlertTriangle,
  TbArrowLeft,
  TbArrowUpRight,
  TbBolt,
  TbDownload,
  TbFilter,
  TbLock,
  TbPlayerPlay,
  TbRefresh,
  TbSearch,
  TbWorld,
  TbX,
} from 'react-icons/tb'
import { startScan, streamScanJob, fetchCountries, fetchIpInfo } from '../api'
import { contributeCountryIntel } from '../intel'
import GeoMap from './GeoMap'
import { tlsExpiryColor } from './IpDetail'
import { enqueueTlsFetch } from '../tlsQueue'

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
  { port: 3306,  label: 'MySQL' },
  { port: 3389,  label: 'RDP' },
  { port: 5432,  label: 'PostgreSQL' },
  { port: 5900,  label: 'VNC' },
  { port: 6379,  label: 'Redis' },
  { port: 8080,  label: 'HTTP-Alt' },
  { port: 8443,  label: 'HTTPS-Alt' },
  { port: 9200,  label: 'Elasticsearch' },
  { port: 27017, label: 'MongoDB' },
]

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

async function _contributeToFirestore(jobId, scanMeta) {
  try {
    const hits = []
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i)
      if (key && key.startsWith('hit_')) {
        try { hits.push(JSON.parse(localStorage.getItem(key))) } catch { /* skip */ }
      }
    }
    await contributeCountryIntel(scanMeta.country, hits, scanMeta)
  } catch { /* silent */ }
}

function severityColor(score) {
  const n = parseFloat(score) || 0
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
  if (!code || code.length !== 2) return ''
  const offset = 0x1F1E6 - 65
  return String.fromCodePoint(code.toUpperCase().charCodeAt(0) + offset) +
         String.fromCodePoint(code.toUpperCase().charCodeAt(1) + offset)
}

const TLS_PORTS = new Set([443, 8443])

function useTlsBadge(ip, port) {
  const [info, setInfo] = useState(null)

  useEffect(() => {
    if (!TLS_PORTS.has(port)) return
    let cancelled = false
    enqueueTlsFetch(ip, port).then(data => {
      if (!cancelled) setInfo(data)
    })
    return () => { cancelled = true }
  }, [ip, port])

  return info
}

function PortChipWithTls({ hit, ip, hasData }) {
  const tls = useTlsBadge(ip, hit.port)

  // TLS badge label
  let tlsBadge = null
  if (tls && !tls.error) {
    const color = tlsExpiryColor(tls.days_left)
    const label = tls.expired
      ? 'EXP'
      : tls.self_signed
        ? 'SELF'
        : tls.days_left !== null
          ? `${tls.days_left}d`
          : 'TLS'
    const title = tls.expired
      ? 'TLS cert expired'
      : tls.self_signed
        ? 'Self-signed certificate'
        : tls.days_left !== null
          ? `TLS cert expires in ${tls.days_left} days`
          : 'TLS cert found'

    tlsBadge = (
      <span
        title={title}
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          marginLeft: 3,
          fontFamily: 'var(--mono-font)',
          fontSize: '0.58rem',
          fontWeight: 700,
          color,
          background: `${color}18`,
          border: `1px solid ${color}55`,
          borderRadius: 2,
          padding: '0px 4px',
          letterSpacing: '0.04em',
          lineHeight: 1.5,
        }}
      >
        {label}
      </span>
    )
  }

  return (
    <span
      className={`port-chip ${hasData ? 'port-chip-hit' : ''}`}
      title={hit.software || (hit.banner ? hit.banner.slice(0, 60) : '')}
      style={{ display: 'inline-flex', alignItems: 'center' }}
    >
      :{hit.port}
      {hit.software && (
        <span className="port-chip-svc"> {hit.software.split('/')[0].slice(0, 12)}</span>
      )}
      {tlsBadge}
    </span>
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
  const [masscanRate,     setMasscanRate]     = useState(300)
  const [nmapParallelism, setNmapParallelism] = useState(100)
  const maxRate = useMemo(() => {
    if (portMode === 'all') return 5000
    if (portMode === 'custom' && customPorts.length > 1000) return 3000
    return 2000
  }, [portMode, customPorts.length])

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
      ? hits.filter(h => h.status !== 'silent')
      : hits
    return base
      .filter(h => matchesPortService(h, portServiceFilter))
      .filter(h => passesSeverity(h))
  }, [hits, onlyFindings, portServiceFilter, severityFilter])

  // ── Port helpers ──────────────────────────────────────────────────────
  const finalPorts = () => {
    if (portMode === 'preset') return PRESET_PORTS
    if (portMode === 'custom') return customPorts
    return []
  }

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

    let savedStatus = 'running'
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
          saved.countryName
            ? `${saved.country} - ${saved.countryName}`
            : saved.country)
        setCountryLocked(true)
      }
      if (saved.probed)    setStats(s => ({ ...s, probed: saved.probed }))
      if (saved.open)      setStats(s => ({ ...s, responsive: saved.open }))
      if (saved.vulns)     setStats(s => ({ ...s, vuln_hosts: saved.vulns }))
      if (saved.status)    savedStatus = saved.status
    } catch { /* ignore */ }

    setJobId(urlJobId)
    setIntelBanner(null)

    // Don't reconnect if job is already finished
    if (['done', 'stopped', 'error'].includes(savedStatus)) {
      setJobStatus(savedStatus)
      // Load hits that were saved during this scan
      const restoredHits = []
      for (let i = 0; i < localStorage.length; i++) {
        const k = localStorage.key(i)
        if (k && k.startsWith('hit_' + urlJobId + '_')) {
          try { restoredHits.push(JSON.parse(localStorage.getItem(k))) } catch { /* skip */ }
        }
      }
      if (restoredHits.length > 0) setHits(restoredHits)
      return
    }

    setJobStatus('running')
    setHits([])
    setStats({ probed: 0, responsive: 0, vuln_hosts: 0 })
    esRef.current?.close()

    esRef.current = streamScanJob(
      urlJobId,
      (event) => {
        if (event.type === 'hit') {
          const hit = event.hit
          setHits(prev => [...prev, hit])
          if (hit.ip && hit.port)
            localStorage.setItem('hit_' + urlJobId + '_' + hit.ip + '_' + hit.port, JSON.stringify(hit))
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
  useEffect(() => {
    if (masscanRate > maxRate) setMasscanRate(maxRate)
  }, [maxRate, masscanRate])

  // ── Scan submit ───────────────────────────────────────────────────────
  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    const rangeList = ranges.split('\n').map(r => r.trim()).filter(Boolean)
    if (!rangeList.length) {
      setError('Enter at least one CIDR range.'); return
    }
    if (portMode === 'custom' && customPorts.length === 0) {
      setError('Add at least one port in Custom mode.'); return
    }

    const safeMasscanRate = Math.min(masscanRate, maxRate)

    try {
      const { job_id } = await startScan({
        ranges:           rangeList,
        ports:            finalPorts(),
        all_ports:        portMode === 'all',
        run_cve:          runCve,
        masscan_rate:     safeMasscanRate,
        scan_mode:        scanMode,
        nmap_parallelism: nmapParallelism,
      })
      localStorage.setItem('scan_' + job_id, JSON.stringify({
        jobId: job_id, country, countryName,
        ranges: rangeList, rangesText: ranges,
        startedAt: Date.now(), status: 'running',
        probed: 0, open: 0, vulns: 0,
        scan_mode: scanMode, nmap_parallelism: nmapParallelism, masscan_rate: safeMasscanRate,
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

  // ── Selection helpers ─────────────────────────────────────────────────
  const toggleSelectIP = (ip) =>
    setSelectedIPs(prev => {
      const next = new Set(prev)
      next.has(ip) ? next.delete(ip) : next.add(ip)
      return next
    })

  const selectAllVisible = () => {
    const ips = [...new Set(visibleHits.map(h => h.ip))]
    setSelectedIPs(new Set(ips))
  }

  const clearSelection = () => setSelectedIPs(new Set())

  const rescanSelected = () => {
    const ipList = [...selectedIPs].join('\n')
    navigate('/scan/new', { state: { ranges: ipList, country, countryName } })
  }

  // ── Export ────────────────────────────────────────────────────────────
  const exportResults = (format) => {
    const data = visibleHits
    if (format === 'json') {
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a'); a.href = url; a.download = 'scan_results.json'; a.click()
    } else {
      const rows = [
        ['ip', 'port', 'software', 'banner', 'cve_ids', 'top_score'].join(','),
        ...data.map(h => [
          h.ip, h.port, h.software || '', (h.banner || '').replace(/\n/g, ' ').slice(0, 80),
          (h.cves || []).map(c => c.id).join(';'),
          hitMaxScore(h),
        ].join(','))
      ].join('\n')
      const blob = new Blob([rows], { type: 'text/csv' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a'); a.href = url; a.download = 'scan_results.csv'; a.click()
    }
  }

  // ── Geo map builder ───────────────────────────────────────────────────
  const buildGeoMap = async () => {
    setGeoLoading(true)
    setGeoError('')
    try {
      const ips = [...new Set(visibleHits.map(h => h.ip))]
      const results = await Promise.all(
        ips.slice(0, 200).map(async (ip) => {
          try {
            const info = await fetchIpInfo(ip)
            const hit  = visibleHits.find(h => h.ip === ip)
            return {
              ip,
              lat: info.lat, lon: info.lon,
              country: info.country, countryCode: info.countryCode,
              city: info.city, isp: info.isp, org: info.org,
              port: hit?.port, software: hit?.software,
            }
          } catch { return null }
        })
      )
      const valid = results.filter(r => r && r.lat && r.lon)
      if (!valid.length) { setGeoError('No geo data available for these IPs.'); return }
      setGeoPoints(valid)
      setGeoMapOpen(true)
    } catch (err) {
      setGeoError(err.message)
    } finally {
      setGeoLoading(false)
    }
  }

  // ─────────────────────────────────────────────────────────────────────
  // Render
  // ─────────────────────────────────────────────────────────────────────
  return (
    <div className="scan-shell">

      {/* ── GeoMap modal ── */}
      {geoMapOpen && geoPoints.length > 0 && (
        <GeoMap points={geoPoints} onClose={() => setGeoMapOpen(false)} />
      )}

      {/* ── Left sidebar: config ── */}
      <aside className="scan-config">
        <div className="scan-config-header">
          <button
            className="back-link"
            onClick={() => navigate('/scan')}
            style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}
          >
            <TbArrowLeft size={14} /> Scan Console
          </button>
          <p className="mono" style={{ display: 'inline-flex', alignItems: 'center', gap: 6, color: 'var(--dim)' }}>
            {scanMode === 'deep'
              ? <><TbSearch size={12} /> Deep Scan</>
              : <><TbBolt size={12} /> Wide Scan</>}
          </p>
          <h2>{countryName || 'New Scan'}</h2>
        </div>

        <form onSubmit={handleSubmit} style={{ display: 'contents' }}>

          {/* Country picker */}
          {!countryLocked && (
            <div className="field">
              <label>Country (intel contribution)</label>
              <div className="combo" style={{ position: 'relative' }}>
                <input
                  value={countryInput}
                  onChange={e => { setCountryInput(e.target.value); setPickerOpen(true) }}
                  onFocus={() => setPickerOpen(true)}
                  onBlur={() => setTimeout(() => setPickerOpen(false), 150)}
                  placeholder="Type country code or name…"
                />
                {pickerOpen && filteredCountries.length > 0 && (
                  <div className="combo-list">
                    {filteredCountries.slice(0, 10).map(c => (
                      <button
                        key={c.code} type="button" className="combo-item"
                        onMouseDown={e => e.preventDefault()}
                        onClick={() => commitCountry(c.code, c.name)}
                      >
                        <span className="mono">{c.code}</span>
                        <span>{c.name}</span>
                      </button>
                    ))}
                  </div>
                )}
              </div>
              {country && (
                <p className="hint" style={{ marginTop: 4 }}>
                  results will be contributed to community intel for {country}
                </p>
              )}
            </div>
          )}

          {countryLocked && (
            <div className="field">
              <label>Country (intel contribution)</label>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <span className="badge">{country}</span>
                <span style={{ fontSize: '0.88rem' }}>{countryName}</span>
                <TbLock size={12} style={{ color: 'var(--dim)', marginLeft: 'auto' }} />
              </div>
              <p className="hint" style={{ marginTop: 4 }}>
                results will be contributed to community intel for {country}
              </p>
            </div>
          )}

          {/* Target ranges */}
          <div className="field">
            <label>Target ranges (CIDR, one per line)</label>
            <textarea
              value={ranges}
              onChange={e => setRanges(e.target.value)}
              rows={5}
              placeholder={'109.175.210.0/24\n185.132.200.0/22'}
            />
            {ranges.trim() && (
              <p className="hint">
                {ranges.split('\n').filter(r => r.trim()).length} range(s) loaded
              </p>
            )}
          </div>

          {/* Scan mode */}
          <div className="field">
            <label>Scan mode</label>
            <div className="scan-mode-row">
              <button
                type="button"
                className={`scan-mode-btn ${scanMode === 'wide' ? 'selected' : ''}`}
                onClick={() => setScanMode('wide')}
              >
                <span className="scan-mode-icon"><TbBolt size={15} /></span>
                <span className="scan-mode-title">Wide Scan</span>
              </button>
              <button
                type="button"
                className={`scan-mode-btn ${scanMode === 'deep' ? 'selected' : ''}`}
                onClick={() => setScanMode('deep')}
              >
                <span className="scan-mode-icon"><TbSearch size={15} /></span>
                <span className="scan-mode-title">Deep Scan</span>
              </button>
            </div>
          </div>

          {/* Port mode */}
          <div className="field">
            <label>Port mode</label>
            <div style={{ display: 'flex', gap: 8, marginTop: 4 }}>
              {['preset', 'custom', 'all'].map(mode => (
                <button
                  key={mode} type="button"
                  className={portMode === mode ? 'primary small' : 'ghost small'}
                  onClick={() => setPortMode(mode)}
                  style={{ textTransform: 'capitalize' }}
                >
                  {mode === 'preset' ? 'CVE Preset' : mode === 'all' ? 'All Ports' : 'Custom'}
                </button>
              ))}
            </div>

            {portMode === 'preset' && (
              <p className="hint" style={{ marginTop: 6, fontSize: '0.68rem', color: 'var(--dim)' }}>
                {PRESET_PORTS.join(', ')}
              </p>
            )}

            {portMode === 'custom' && (
              <div className="port-picker" ref={portDropRef}>
                <div className="port-tags">
                  {customPorts.map(p => (
                    <span key={p} className="port-tag">
                      {p}
                      <button
                        type="button"
                        className="port-tag-remove"
                        onClick={() => removeCustomPort(p)}
                      >
                        <TbX size={10} />
                      </button>
                    </span>
                  ))}
                  <input
                    className="port-tag-input"
                    value={portSearch}
                    placeholder="Add port…"
                    onChange={e => { setPortSearch(e.target.value); setPortDropOpen(true) }}
                    onFocus={() => setPortDropOpen(true)}
                    onKeyDown={handlePortSearchKey}
                  />
                </div>
                {portDropOpen && (
                  <div className="port-dropdown">
                    {filteredPortList.slice(0, 12).map(p => (
                      <button key={p.port} type="button" className="port-drop-item"
                        onClick={() => { toggleCustomPort(p.port); setPortSearch(''); setPortDropOpen(false) }}
                      >
                        <span className="mono">{p.port}</span>
                        <span className="port-drop-label">{p.label}</span>
                        {customPorts.includes(p.port) && (
                          <span style={{ marginLeft: 'auto', color: 'var(--cyan)' }}>✓</span>
                        )}
                      </button>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Rate — wide scan only */}
          {scanMode === 'wide' && (
            <div className="field">
              <label style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <span>Rate (pps)</span>
                <span className="mono" style={{ color: 'var(--cyan)', fontSize: '0.78rem' }}>
                  {masscanRate.toLocaleString()} pps
                </span>
              </label>
              <input
                type="range"
                min={50}
                max={maxRate}
                step={50}
                value={masscanRate}
                onChange={e => setMasscanRate(Number(e.target.value))}
              />
              <p
                className="hint"
                style={{
                  color: masscanRate > 1500 ? 'var(--high)' : masscanRate >= 900 ? 'var(--med)' : 'var(--dim)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 5,
                  marginTop: 6,
                }}
              >
                <TbAlertTriangle size={13} />
                {masscanRate > 1500
                  ? 'High rate may miss hosts. Suggested 500–1500 pps for accuracy.'
                  : 'Higher rates finish faster but can miss hosts; 500–1500 pps is a good balance.'}
              </p>
            </div>
          )}

          {/* Parallelism (deep scan only) */}
          {scanMode === 'deep' && (
            <div className="field">
              <label>Scan parallelism (1–500)</label>
              <input
                type="number" min={1} max={500}
                value={nmapParallelism}
                onChange={e => setNmapParallelism(Number(e.target.value))}
              />
            </div>
          )}

          {/* CVE toggle */}
          <label className="switch-row">
            <input type="checkbox" checked={runCve} onChange={e => setRunCve(e.target.checked)} />
            NVD CVE lookup per banner
          </label>

          {/* Actions */}
          <div className="scan-actions">
            <button
              type="submit"
              className="primary"
              style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}
              disabled={jobStatus === 'running'}
            >
              {jobStatus === 'running'
                ? <><TbRefresh size={14} className="spin" /> Scanning…</>
                : <><TbPlayerPlay size={14} /> Start Scan</>}
            </button>
            {jobStatus === 'running' && (
              <button type="button" className="ghost" onClick={handleStop}
                style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}
              >
                <TbX size={14} /> Stop
              </button>
            )}
          </div>
        </form>

        {/* Stats */}
        <div className="scan-stats">
          <div className="scan-stat-item">
            <span className="label">Probed</span>
            <span className="val">{stats.probed.toLocaleString()}</span>
          </div>
          <div className="scan-stat-item">
            <span className="label">Open</span>
            <span className="val" style={{ color: 'var(--cyan)' }}>{stats.responsive.toLocaleString()}</span>
          </div>
          <div className="scan-stat-item">
            <span className="label">Vulns</span>
            <span className="val" style={{ color: 'var(--high)' }}>{stats.vuln_hosts.toLocaleString()}</span>
          </div>
        </div>

        {jobId && (
          <p className="hint" style={{ marginTop: 8, wordBreak: 'break-all', fontFamily: 'var(--mono-font)', fontSize: '0.65rem' }}>
            job: {jobId}
          </p>
        )}
        {jobStatus && !['running', 'intel'].includes(jobStatus) && (
          <p className={`scan-status-badge ${jobStatus}`}>{jobStatus.toUpperCase()}</p>
        )}
        {error && (
          <p className="error">
            <TbAlertTriangle size={13} /> {error}
          </p>
        )}
      </aside>

      {/* ── Right panel: hit stream ── */}
      <div className="scan-main" style={{ display: 'flex', flexDirection: 'column', minHeight: 0, overflow: 'hidden' }}>

        {/* Intel banner */}
        {intelBanner && (
          <div className="intel-scan-banner">
            <TbBolt size={13} style={{ color: 'var(--cyan)', flexShrink: 0 }} />
            Community data for {intelBanner.country}
            {intelBanner.age_days > 0 ? ` — scanned ${intelBanner.age_days}d ago` : ' — fresh'}
            <button className="ghost small" style={{ marginLeft: 16, fontSize: '0.72rem' }}
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
                <TbFilter size={13} style={{ flexShrink: 0 }} />
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

            <label className="hit-filter-toggle" title="Hide silent hosts (no open ports)">
              <input type="checkbox" checked={onlyFindings}
                onChange={e => { setOnlyFindings(e.target.checked); setSelectedIPs(new Set()) }} />
              <span>Only findings</span>
              <span className="hit-filter-count">
                {onlyFindings
                  ? `${visibleHits.length} / ${hits.length}`
                  : `all ${hits.length}`}
              </span>
            </label>

            <div className="hit-toolbar-sep" />

            <button className="ghost small" onClick={selectAllVisible}>Select all</button>
            {selectedIPs.size > 0 && (
              <>
                <button className="ghost small" onClick={clearSelection}>
                  Clear ({selectedIPs.size})
                </button>
                <button
                  className="primary small"
                  onClick={rescanSelected}
                  style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}
                >
                  <TbPlayerPlay size={11} /> Re-scan {selectedIPs.size} IP{selectedIPs.size > 1 ? 's' : ''}
                </button>
              </>
            )}

            <div className="hit-toolbar-sep" />

            <div className="hit-export-group">
              <button className="ghost small" onClick={() => exportResults('csv')}
                style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
                <TbDownload size={13} /> CSV
              </button>
              <button className="ghost small" onClick={() => exportResults('json')}
                style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
                <TbDownload size={13} /> JSON
              </button>
            </div>

            <button
              className="ghost small"
              onClick={buildGeoMap}
              disabled={geoLoading}
              style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}
            >
              <TbWorld size={13} />
              {geoLoading ? 'Mapping…' : 'Geo map'}
            </button>
          </div>
        )}

        {geoError && (
          <p className="error" style={{ margin: '8px 16px' }}>
            <TbAlertTriangle size={13} /> {geoError}
          </p>
        )}

        {/* Hit stream */}
        <div className="hit-stream" ref={logRef}>
          {hits.length === 0 && (
            <div className="hit-empty">
              {jobStatus === 'running'
                ? <><span className="pulse-dot" /> Waiting for open ports…</>
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
              const isActive    = activeHit === ip
              const isSelected  = selectedIPs.has(ip)
              const allCves     = ports.flatMap(p => p.cves || [])
              const topCveScore = allCves.length
                ? Math.max(...allCves.map(c => parseFloat(c.score || '0') || 0))
                : 0

              return (
                <div
                  key={ip}
                  className={`hit-row ${isActive ? 'active' : ''} ${isSelected ? 'selected' : ''} ${topCveScore > 0 ? 'has-cve' : ''}`}
                  onClick={() => setActiveHit(isActive ? null : ip)}
                >
                  <div className="hit-row-check" onClick={e => e.stopPropagation()}>
                    <input
                      type="checkbox"
                      checked={isSelected}
                      onChange={() => toggleSelectIP(ip)}
                    />
                  </div>

                  <div className="hit-row-body">
                    <div className="hit-row-main">
                      <span className="mono hit-ip">{ip}</span>

                      <span className="hit-flag" aria-hidden>{countryFlag(country)}</span>

                      <div className="port-chip-row">
                        {ports.every(p => p.status === 'silent')
                          ? <span className="hint" style={{ fontSize: '0.72rem' }}>no response</span>
                          : ports.map((p, pi) => {
                              const hasData = !!(p.banner || p.software || p.cves?.length)
                              return (
                                <PortChipWithTls
                                  key={pi}
                                  hit={p}
                                  ip={ip}
                                  hasData={hasData}
                                />
                              )
                            })
                        }
                      </div>

                      {topCveScore > 0 && (
                        <span
                          className="cve-badge"
                          style={{
                            background: severityColor(topCveScore),
                            color: '#000',
                            fontFamily: 'var(--mono-font)',
                            fontSize: '0.65rem',
                            fontWeight: 700,
                            padding: '2px 7px',
                            borderRadius: 2,
                            marginLeft: 4,
                          }}
                        >
                          CVE {topCveScore}
                        </span>
                      )}

                      {allCves.length > 0 && (
                        <span className="hint" style={{ fontFamily: 'var(--mono-font)', fontSize: '0.7rem', marginLeft: 4 }}>
                          {allCves.length} vuln{allCves.length !== 1 ? 's' : ''}
                        </span>
                      )}
                    </div>

                    {isActive && (
                      <div className="hit-detail">
                        {ports.map((p, pi) => (
                          <div key={pi} className="hit-port-section">
                            <div className="hit-port-section-header">
                              <span className="mono" style={{ color: 'var(--cyan)' }}>:{p.port}</span>
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
                                      <span
                                        className="score-pill"
                                        style={{ color: severityColor(cve.score) }}
                                      >
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
                        <button
                          className="ip-detail-link"
                          onClick={e => {
                            e.stopPropagation()
                            window.open('/ip/' + encodeURIComponent(ip), '_blank')
                          }}
                          style={{ display: 'inline-flex', alignItems: 'center', gap: 6, marginTop: 4 }}
                        >
                          View IP detail <TbArrowUpRight size={13} />
                        </button>
                      </div>
                    )}
                  </div>
                </div>
              )
            })
          })()}
        </div>
      </div>
    </div>
  )
}
