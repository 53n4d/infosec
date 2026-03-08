import { useState, useEffect, useRef, useCallback, useMemo } from 'react'
import { useLocation } from 'react-router-dom'
import { startScan, streamScanJob } from '../api'

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
  const location = useLocation()
  const [ranges, setRanges] = useState('')

  // Populate ranges whenever we navigate here with state from RangeLookup
  useEffect(() => {
    if (location.state?.ranges) {
      setRanges(location.state.ranges)
      // Clear the state so a manual refresh doesn't re-populate
      window.history.replaceState({}, '')
    }
  }, [location.state])

  // Port mode
  const [portMode, setPortMode] = useState('preset')
  const [customPorts, setCustomPorts] = useState([])   // array of port numbers
  const [portSearch, setPortSearch] = useState('')
  const [portDropOpen, setPortDropOpen] = useState(false)
  const portDropRef = useRef(null)

  const [runCve, setRunCve] = useState(true)
  const [masscanRate, setMasscanRate] = useState(1000)

  const [jobId, setJobId] = useState(null)
  const [jobStatus, setJobStatus] = useState(null)
  const [stats, setStats] = useState({ probed: 0, responsive: 0, vuln_hosts: 0 })
  const [hits, setHits] = useState([])
  const [error, setError] = useState('')
  const [activeHit, setActiveHit] = useState(null)

  const esRef = useRef(null)
  const logRef = useRef(null)

  // Close port dropdown on outside click
  useEffect(() => {
    const handler = (e) => {
      if (portDropRef.current && !portDropRef.current.contains(e.target)) {
        setPortDropOpen(false)
      }
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  const scrollLog = useCallback(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight
  }, [])

  useEffect(() => { scrollLog() }, [hits, scrollLog])
  useEffect(() => () => esRef.current?.close(), [])

  // Filtered port list for dropdown
  const filteredPortList = useMemo(() => {
    const term = portSearch.toLowerCase().trim()
    if (!term) return ALL_PORTS
    return ALL_PORTS.filter(
      (p) => p.port.toString().includes(term) || p.label.toLowerCase().includes(term)
    )
  }, [portSearch])

  const toggleCustomPort = (port) => {
    setCustomPorts((prev) =>
      prev.includes(port) ? prev.filter((p) => p !== port) : [...prev, port].sort((a, b) => a - b)
    )
  }

  const removeCustomPort = (port) => setCustomPorts((prev) => prev.filter((p) => p !== port))

  const addCustomPortByInput = (val) => {
    const n = parseInt(val, 10)
    if (n > 0 && n <= 65535 && !customPorts.includes(n)) {
      setCustomPorts((prev) => [...prev, n].sort((a, b) => a - b))
    }
    setPortSearch('')
  }

  const handlePortSearchKey = (e) => {
    if ((e.key === 'Enter' || e.key === ',') && portSearch.trim()) {
      e.preventDefault()
      addCustomPortByInput(portSearch.trim())
    }
  }

  const finalPorts = () => {
    if (portMode === 'all') return []
    if (portMode === 'preset') return PRESET_PORTS
    return customPorts
  }

  const handleStart = async (e) => {
    e.preventDefault()
    setError('')
    setHits([])
    setStats({ probed: 0, responsive: 0, vuln_hosts: 0 })
    setJobStatus(null)
    setJobId(null)
    setActiveHit(null)

    const rangeList = ranges.split(/[\s,\n]+/).map((r) => r.trim()).filter(Boolean)
    if (!rangeList.length) { setError('Enter at least one CIDR range.'); return }
    if (portMode === 'custom' && customPorts.length === 0) { setError('Add at least one port in Custom mode.'); return }

    try {
      const { job_id } = await startScan({
        ranges: rangeList,
        ports: finalPorts(),
        all_ports: portMode === 'all',
        run_cve: runCve,
        masscan_rate: masscanRate,
      })
      setJobId(job_id)
      setJobStatus('running')
      esRef.current?.close()
      esRef.current = streamScanJob(
        job_id,
        (event) => {
          if (event.type === 'hit') setHits((prev) => [...prev, event.hit])
          else if (event.type === 'stats') {
            setStats({ probed: event.probed, responsive: event.responsive, vuln_hosts: event.vuln_hosts })
            setJobStatus(event.status)
          }
        },
        () => setJobStatus('done'),
        () => setJobStatus('error'),
      )
    } catch (err) {
      setError(err.message)
    }
  }

  const handleStop = () => { esRef.current?.close(); setJobStatus('stopped') }

  return (
    <div className="scan-shell">
      {/* ── Config panel ── */}
      <aside className="scan-config">
        <div className="scan-config-header">
          <p className="mono">masscan → banner → NVD</p>
          <h2>Scan Console</h2>
        </div>

        <form className="form" onSubmit={handleStart}>
          {/* Target ranges */}
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

          {/* Port mode */}
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

            {/* Preset info */}
            {portMode === 'preset' && (
              <p className="hint mono" style={{ fontSize: '0.7rem', marginTop: 6, lineHeight: 1.6 }}>
                {PRESET_PORTS.join(', ')}
              </p>
            )}

            {/* All ports warning */}
            {portMode === 'all' && (
              <p className="hint" style={{ marginTop: 6 }}>⚠ 1–65535 — requires masscan installed</p>
            )}

            {/* Custom port picker */}
            {portMode === 'custom' && (
              <div className="port-picker" ref={portDropRef}>
                {/* Selected port tags */}
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

                {/* Search input */}
                <div className="port-search-wrap">
                  <input
                    value={portSearch}
                    onChange={(e) => { setPortSearch(e.target.value); setPortDropOpen(true) }}
                    onFocus={() => setPortDropOpen(true)}
                    onKeyDown={handlePortSearchKey}
                    placeholder="Search port or service… (Enter to add custom)"
                    autoComplete="off"
                  />
                  {customPorts.length > 0 && (
                    <button type="button" className="ghost small" onClick={() => setCustomPorts([])}>Clear</button>
                  )}
                </div>

                {/* Dropdown */}
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

          {/* Rate */}
          <div className="field">
            <label>masscan rate (pps)</label>
            <input type="number" value={masscanRate} min={100} max={100000}
              onChange={(e) => setMasscanRate(Number(e.target.value))} />
          </div>

          {/* CVE toggle */}
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

        {jobId && <p className="hint mono" style={{ marginTop: 8, wordBreak: 'break-all' }}>job: {jobId}</p>}
        {jobStatus && jobStatus !== 'running' && (
          <p className={`scan-status-badge ${jobStatus}`}>{jobStatus.toUpperCase()}</p>
        )}
        {error && <p className="error">{error}</p>}
      </aside>

      {/* ── Hit stream ── */}
      <div className="scan-main">
        <div className="hit-stream" ref={logRef}>
          {hits.length === 0 && (
            <div className="hit-empty">
              {jobStatus === 'running'
                ? <><span className="pulse-dot" /> waiting for open ports...</>
                : 'No hits yet. Configure and start a scan.'}
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
                  <a
                    className="ip-detail-link"
                    href={`/ip/${encodeURIComponent(hit.ip)}`}
                    target="_blank"
                    rel="noreferrer"
                    onClick={(e) => {
                      e.preventDefault()
                      const w = window.open(`/ip/${encodeURIComponent(hit.ip)}`, '_blank')
                      // pass hit via sessionStorage so new tab can read it
                      sessionStorage.setItem(`hit_${hit.ip}_${hit.port}`, JSON.stringify(hit))
                      w.focus()
                    }}
                  >
                    View IP detail →
                  </a>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}