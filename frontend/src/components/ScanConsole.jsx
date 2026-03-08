import { useState, useEffect, useRef, useCallback, useMemo } from 'react'
import { useLocation, useNavigate, useParams } from 'react-router-dom'
import { startScan, streamScanJob, contributeIntel } from '../api'

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

export default function ScanConsole() {
  const location  = useLocation()
  const navigate  = useNavigate()
  const { jobId: urlJobId } = useParams()

  const [ranges,      setRanges]      = useState('')
  const [portMode,    setPortMode]    = useState('preset')
  const [customPorts, setCustomPorts] = useState([])
  const [portSearch,  setPortSearch]  = useState('')
  const [portDropOpen,setPortDropOpen]= useState(false)
  const portDropRef = useRef(null)

  const [runCve,       setRunCve]       = useState(true)
  const [masscanRate,  setMasscanRate]  = useState(1000)

  const [jobId,      setJobId]      = useState(urlJobId || null)
  const [jobStatus,  setJobStatus]  = useState(null)
  const [stats,      setStats]      = useState({ probed: 0, responsive: 0, vuln_hosts: 0 })
  const [hits,       setHits]       = useState([])
  const [error,      setError]      = useState('')
  const [activeHit,  setActiveHit]  = useState(null)

  // Intel banner — shown when data was loaded from community intel
  const [intelBanner, setIntelBanner] = useState(null)

  const esRef  = useRef(null)
  const logRef = useRef(null)

  // ── Populate from navigation state (RangeLookup / ScanDashboard) ──────
  useEffect(() => {
    if (!location.state) return
    const { ranges: r, intelHits, intelCountry, autoStart } = location.state

    if (r) setRanges(r)

    if (intelHits && intelHits.length > 0) {
      // Pre-load intel hits as read-only results
      setHits(intelHits)
      setStats({
        probed: location.state.intelStats?.probed || 0,
        responsive: intelHits.length,
        vuln_hosts: intelHits.filter((h) => h.cves?.length > 0).length,
      })
      setJobStatus('intel')
      setIntelBanner({
        country: intelCountry,
        age_days: location.state.age_days || 0,
      })
    }

    window.history.replaceState({}, '')
  }, [location.state])

  // ── Reconnect to existing job from URL ────────────────────────────────
  useEffect(() => {
    if (!urlJobId) return

    try {
      const saved = JSON.parse(localStorage.getItem('scan_' + urlJobId) || '{}')
      if (saved.rangesText) setRanges(saved.rangesText)
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
          setHits((prev) => [...prev, event.hit])
        } else if (event.type === 'stats') {
          const s = { probed: event.probed, responsive: event.responsive, vuln_hosts: event.vuln_hosts }
          setStats(s)
          setJobStatus(event.status)
          const existing = JSON.parse(localStorage.getItem('scan_' + urlJobId) || '{}')
          localStorage.setItem('scan_' + urlJobId, JSON.stringify({
            ...existing,
            status: event.status,
            probed: event.probed,
            open: event.responsive,
            vulns: event.vuln_hosts,
          }))
        }
      },
      () => {
        setJobStatus('done')
        const existing = JSON.parse(localStorage.getItem('scan_' + urlJobId) || '{}')
        const updated = { ...existing, status: 'done' }
        localStorage.setItem('scan_' + urlJobId, JSON.stringify(updated))
        // Contribute to community intel when scan finishes
        _contributeIfPossible(urlJobId, updated)
      },
      () => {
        setJobStatus('error')
        const existing = JSON.parse(localStorage.getItem('scan_' + urlJobId) || '{}')
        localStorage.setItem('scan_' + urlJobId, JSON.stringify({ ...existing, status: 'error' }))
      },
    )
    return () => esRef.current?.close()
  }, [urlJobId])

  // ── Close port dropdown on outside click ──────────────────────────────
  useEffect(() => {
    const handler = (e) => {
      if (portDropRef.current && !portDropRef.current.contains(e.target))
        setPortDropOpen(false)
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  const scrollLog = useCallback(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight
  }, [])

  useEffect(() => { scrollLog() }, [hits, scrollLog])
  useEffect(() => () => esRef.current?.close(), [])

  const filteredPortList = useMemo(() => {
    const term = portSearch.toLowerCase().trim()
    if (!term) return ALL_PORTS
    return ALL_PORTS.filter(
      (p) => p.port.toString().includes(term) || p.label.toLowerCase().includes(term)
    )
  }, [portSearch])

  const toggleCustomPort = (port) =>
    setCustomPorts((prev) =>
      prev.includes(port) ? prev.filter((p) => p !== port) : [...prev, port].sort((a, b) => a - b)
    )

  const removeCustomPort = (port) => setCustomPorts((prev) => prev.filter((p) => p !== port))

  const addCustomPortByInput = (val) => {
    const n = parseInt(val, 10)
    if (n > 0 && n <= 65535 && !customPorts.includes(n))
      setCustomPorts((prev) => [...prev, n].sort((a, b) => a - b))
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

  // ── Contribute finished scan to Firestore intel ────────────────────────
  const _contributeIfPossible = (jid, savedMeta) => {
    try {
      // Pull full hits from localStorage hit keys
      const hitList = []
      for (let i = 0; i < localStorage.length; i++) {
        const k = localStorage.key(i)
        if (k && k.startsWith('hit_')) {
          try { hitList.push(JSON.parse(localStorage.getItem(k))) } catch { /* ignore */ }
        }
      }
      // Determine country from ranges if available
      const country = savedMeta?.country || null
      if (!country) return  // can't contribute without country

      contributeIntel(country, {
        country_name: savedMeta.country_name || '',
        ranges: savedMeta.ranges || [],
        probed: savedMeta.probed || 0,
        open: savedMeta.open || 0,
        vulns: savedMeta.vulns || 0,
        hits: hitList.slice(0, 500),
      }).catch(() => { /* silent fail — intel contribution is best-effort */ })
    } catch { /* ignore */ }
  }

  // ── Start a new scan ───────────────────────────────────────────────────
  const handleStart = async (e) => {
    e.preventDefault()
    setError('')
    setHits([])
    setStats({ probed: 0, responsive: 0, vuln_hosts: 0 })
    setJobStatus(null)
    setJobId(null)
    setActiveHit(null)
    setIntelBanner(null)

    const rangeList = ranges.split(/[\s,\n]+/).map((r) => r.trim()).filter(Boolean)
    if (!rangeList.length) { setError('Enter at least one CIDR range.'); return }
    if (portMode === 'custom' && customPorts.length === 0) {
      setError('Add at least one port in Custom mode.')
      return
    }

    try {
      const { job_id } = await startScan({
        ranges: rangeList,
        ports: finalPorts(),
        all_ports: portMode === 'all',
        run_cve: runCve,
        masscan_rate: masscanRate,
      })

      localStorage.setItem('scan_' + job_id, JSON.stringify({
        jobId:      job_id,
        ranges:     rangeList,
        rangesText: ranges,
        startedAt:  Date.now(),
        status:     'running',
        probed:     0,
        open:       0,
        vulns:      0,
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
      {/* ── Left panel: config ─────────────────────────────────────────── */}
      <aside className="scan-config">
        <div className="scan-config-header">
          <button className="back-link" onClick={() => navigate('/scan')}>← Scan Console</button>
          <p className="mono">masscan → banner → NVD</p>
          <h2>Scan {urlJobId ? urlJobId.slice(0, 8) + '…' : 'New'}</h2>
        </div>

        <form className="form" onSubmit={handleStart}>
          <div className="field">
            <label>Target ranges (CIDR, one per line)</label>
            <textarea
              rows={6}
              value={ranges}
              onChange={(e) => setRanges(e.target.value)}
              placeholder={"192.168.1.0/24\n10.0.0.0/8\n203.0.113.0/28"}
              spellCheck={false}
            />
            <p className="hint">
              {ranges.trim()
                ? `${ranges.trim().split(/\n/).filter(Boolean).length} range(s) loaded`
                : 'Paste CIDRs or use Range Pull to populate'}
            </p>
          </div>

          <div className="field">
            <label>Port mode</label>
            <div className="pill-row">
              {[
                { id: 'preset', label: 'CVE Preset' },
                { id: 'custom', label: 'Custom' },
                { id: 'all',    label: 'All Ports' },
              ].map((m) => (
                <button key={m.id} type="button"
                  className={portMode === m.id ? 'pill selected' : 'pill'}
                  onClick={() => setPortMode(m.id)}>
                  {m.label}
                </button>
              ))}
            </div>

            {portMode === 'preset' && (
              <p className="hint mono" style={{ fontSize: '0.7rem', marginTop: 6, lineHeight: 1.6 }}>
                {PRESET_PORTS.join(', ')}
              </p>
            )}

            {portMode === 'all' && (
              <p className="hint" style={{ marginTop: 6 }}>⚠ 1–65535 — requires masscan installed</p>
            )}

            {portMode === 'custom' && (
              <div className="port-picker" ref={portDropRef}>
                <div className="port-tags">
                  {customPorts.length === 0 && (
                    <span className="hint" style={{ padding: '4px 2px' }}>No ports selected yet</span>
                  )}
                  {customPorts.map((p) => {
                    const info = ALL_PORTS.find((x) => x.port === p)
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
                  <input
                    value={portSearch}
                    onChange={(e) => { setPortSearch(e.target.value); setPortDropOpen(true) }}
                    onFocus={() => setPortDropOpen(true)}
                    onKeyDown={handlePortSearchKey}
                    placeholder="Search port or service… (Enter to add)"
                    autoComplete="off"
                  />
                  {customPorts.length > 0 && (
                    <button type="button" className="ghost small" onClick={() => setCustomPorts([])}>Clear</button>
                  )}
                </div>
                {portDropOpen && (
                  <div className="port-drop">
                    {filteredPortList.length === 0 && (
                      <div className="port-drop-empty">No matches — press Enter to add {portSearch}</div>
                    )}
                    {filteredPortList.map((p) => (
                      <button
                        key={p.port}
                        type="button"
                        className={`port-drop-item ${customPorts.includes(p.port) ? 'selected' : ''}`}
                        onMouseDown={(e) => e.preventDefault()}
                        onClick={() => toggleCustomPort(p.port)}
                      >
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

          <div className="field">
            <label>masscan rate (pps)</label>
            <input
              type="number" value={masscanRate} min={100} max={100000}
              onChange={(e) => setMasscanRate(Number(e.target.value))}
            />
          </div>

          <div className="switch-row">
            <label>
              <input type="checkbox" checked={runCve} onChange={(e) => setRunCve(e.target.checked)} />
              NVD CVE lookup per banner
            </label>
          </div>

          <div className="scan-actions">
            <button type="submit" className="primary" disabled={jobStatus === 'running'}>
              {jobStatus === 'running' ? '⟳ Scanning...' : '▶ Start Scan'}
            </button>
            {jobStatus === 'running' && (
              <button type="button" className="ghost" onClick={handleStop}>■ Stop</button>
            )}
          </div>
        </form>

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

      {/* ── Right panel: hit stream ────────────────────────────────────── */}
      <div className="scan-main">
        {/* Community intel banner */}
        {intelBanner && (
          <div className="intel-scan-banner">
            <span style={{ color: 'var(--accent)', marginRight: 8 }}>⚡</span>
            Community data
            {intelBanner.age_days > 0
              ? ` — last scanned ${intelBanner.age_days}d ago`
              : ' — scanned recently'
            }
            <button
              className="ghost small"
              style={{ marginLeft: 16, fontSize: '0.75rem' }}
              onClick={() => {
                setIntelBanner(null)
                setHits([])
                setStats({ probed: 0, responsive: 0, vuln_hosts: 0 })
                setJobStatus(null)
              }}
            >
              Run fresh scan
            </button>
          </div>
        )}

        <div className="hit-stream" ref={logRef}>
          {hits.length === 0 && (
            <div className="hit-empty">
              {jobStatus === 'running'
                ? <><span className="pulse-dot" /> waiting for open ports...</>
                : 'No hits yet. Configure and start a scan, or load community intel from the dashboard.'}
            </div>
          )}

          {hits.map((hit, i) => (
            <div
              key={i}
              className={`hit-row ${activeHit === i ? 'active' : ''} ${hit.cves?.length ? 'has-cve' : ''}`}
              onClick={() => setActiveHit(activeHit === i ? null : i)}
            >
              <div className="hit-main-line">
                <span className="status-dot open" />
                <span className="mono hit-ip">{hit.ip}</span>
                <span className="hit-port">:{hit.port}</span>
                {hit.software && <span className="hit-software">{hit.software}</span>}
                {hit.cves?.length > 0 && (
                  <span className="cve-badge">{hit.cves.length} CVE{hit.cves.length > 1 ? 's' : ''}</span>
                )}
              </div>

              {activeHit === i && (
                <div className="hit-detail">
                  {hit.banner && <pre className="banner-pre">{hit.banner}</pre>}
                  {hit.version_info?.length > 0 && (
                    <div className="version-tags">
                      {hit.version_info.map((vi, j) => (
                        <span key={j} className="version-tag">
                          <span className="mono">{vi.label}</span> {vi.value}
                        </span>
                      ))}
                    </div>
                  )}
                  {hit.cves?.length > 0 && (
                    <div className="cve-detail-list">
                      {hit.cves.map((cve, j) => (
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
                  <button
                    className="ip-detail-link"
                    onClick={(e) => {
                      e.stopPropagation()
                      navigate('/ip/' + encodeURIComponent(hit.ip), { state: { hit } })
                    }}
                  >
                    View IP detail →
                  </button>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}