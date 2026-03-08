import { useEffect, useMemo, useState } from 'react'
import { fetchCountries, fetchRanges, runScan } from '../api'

const COMMON_PORTS = [
  21, 22, 23, 25, 53, 80, 110, 123, 135, 137, 139, 143, 161, 389, 443, 445, 465, 587, 636, 993, 995,
  1025, 1433, 1521, 2049, 2083, 2375, 2376, 2377, 27017, 3000, 3306, 3389, 3690, 4444, 5000, 5432, 5601,
  5672, 5900, 5984, 5985, 6379, 6443, 7001, 8000, 8008, 8080, 8088, 8443, 9000, 9200, 9300, 10000,
]

const ipToInt = (ip) => {
  return ip.split('.').reduce((acc, oct) => (acc << 8n) + BigInt(parseInt(oct, 10)), 0n)
}

const intToIp = (intVal) => {
  return [24n, 16n, 8n, 0n].map((shift) => Number((intVal >> shift) & 255n)).join('.')
}

const cidrToSampleIps = (cidr, limit = 128) => {
  try {
    const [ip, prefix] = cidr.split('/')
    const base = ipToInt(ip)
    const maskBits = 32 - Number(prefix || 32)
    const size = 1n << BigInt(maskBits)
    const count = BigInt(Math.min(limit, Number(size)))
    const ips = []
    for (let i = 0n; i < count; i++) {
      ips.push(intToIp(base + i))
    }
    return ips
  } catch (e) {
    return []
  }
}

export default function RangeLookup() {
  const [countries, setCountries] = useState([])
  const [country, setCountry] = useState('')
  const [countryInput, setCountryInput] = useState('')
  const [pickerOpen, setPickerOpen] = useState(false)
  const rirOptions = useMemo(() => ['RIPE', 'ARIN', 'APNIC', 'LACNIC', 'AFRINIC'], [])
  const [selectedRirs, setSelectedRirs] = useState(rirOptions)
  const [force, setForce] = useState(false)
  const [runMasscan, setRunMasscan] = useState(false)
  const [runCve, setRunCve] = useState(false)
  const [allPorts, setAllPorts] = useState(true)
  const [selectedPorts, setSelectedPorts] = useState([])
  const [portInput, setPortInput] = useState('')
  const [portPickerOpen, setPortPickerOpen] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState(null)
  const [selectedRanges, setSelectedRanges] = useState([])
  const [activeRange, setActiveRange] = useState(null)
  const [selectedIp, setSelectedIp] = useState(null)
  const [masscanHits, setMasscanHits] = useState([])

  const extractCode = (val) => val.trim().slice(0, 2).toUpperCase()

  useEffect(() => {
    fetchCountries()
      .then((data) => {
        setCountries(data)
        if (data.length) {
          setCountry(data[0].code)
          setCountryInput(`${data[0].code} - ${data[0].name}`)
        }
      })
      .catch((err) => setError(err.message))
  }, [])

  useEffect(() => {
    setSelectedRirs(rirOptions)
  }, [rirOptions])

  const filteredCountries = useMemo(() => {
    const term = countryInput.toLowerCase()
    if (!term.trim()) return countries
    return countries.filter(
      (c) => c.code.toLowerCase().includes(term) || c.name.toLowerCase().includes(term)
    )
  }, [countries, countryInput])

  const filteredPorts = useMemo(() => {
    if (!portInput.trim()) return COMMON_PORTS
    const term = portInput.trim()
    return COMMON_PORTS.filter((p) => p.toString().startsWith(term)).slice(0, 20)
  }, [portInput])

  const toggleRir = (name) => {
    setSelectedRirs((prev) => (prev.includes(name) ? prev.filter((r) => r !== name) : [...prev, name]))
  }

  const commitCountry = (code) => {
    const found = countries.find((c) => c.code === code)
    setCountry(code)
    setCountryInput(found ? `${found.code} - ${found.name}` : code)
    setPickerOpen(false)
  }

  const handleBlur = () => {
    setTimeout(() => setPickerOpen(false), 120)
    if (!country && filteredCountries.length) {
      commitCountry(filteredCountries[0].code)
    }
  }

  const onSubmit = async (e) => {
    e.preventDefault()
    if (!country) return
    setError('')
    setLoading(true)
    setResult(null)
    try {
      const data = await fetchRanges({ country, rirs: selectedRirs, force })
      setResult({
        ...data,
        config: {
          rirs: selectedRirs,
          country,
          runMasscan: false,
          runCve: false,
          allPorts,
          ports: selectedPorts,
        },
        masscan_hits: [],
      })
      setRunMasscan(false)
      setRunCve(false)
      setSelectedRanges(data.ranges)
      setActiveRange(data.ranges[0] || null)
      setMasscanHits([])
      setSelectedIp(null)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const addPort = (val) => {
    const num = Number(val)
    if (!Number.isInteger(num) || num < 1 || num > 65535) return
    setSelectedPorts((prev) => {
      if (prev.includes(num)) return prev
      return [...prev, num].sort((a, b) => a - b)
    })
  }

  const handlePortKey = (e) => {
    if (e.key === 'Enter' || e.key === ',') {
      e.preventDefault()
      addPort(portInput)
      setPortInput('')
    }
  }

  const clearPorts = () => {
    setSelectedPorts([])
  }

  const hasResult = Boolean(result)
  const selectedRange = activeRange
  const selectedRangeIps = useMemo(() => {
    if (!hasResult) return []
    return masscanHits.filter((hit) => hit.range === selectedRange)
  }, [hasResult, masscanHits, selectedRange])
  const sampleIps = useMemo(() => (selectedRange ? cidrToSampleIps(selectedRange, 128) : []), [selectedRange])

  const toggleRange = (cidr) => {
    setSelectedRanges((prev) => {
      const exists = prev.includes(cidr)
      const next = exists ? prev.filter((r) => r !== cidr) : [...prev, cidr]
      setActiveRange(next[0] || null)
      return next
    })
  }

  const selectAllRanges = (checked) => {
    if (!result?.ranges) return
    if (checked) {
      setSelectedRanges(result.ranges)
      setActiveRange(result.ranges[0] || null)
    } else {
      setSelectedRanges([])
      setActiveRange(null)
    }
  }

  const onRunScans = () => {
    if (!runMasscan && !runCve) return
    const payload = {
      ranges: selectedRanges,
      ports: allPorts ? [] : selectedPorts,
      all_ports: allPorts,
      run_cve: runCve,
    }
    // set interim state to scanning
    const pendingHits = []
    selectedRanges.forEach((range) => {
      const ips = cidrToSampleIps(range, 20)
      ips.forEach((ip) => pendingHits.push({ range, ip, status: 'scanning', ports: [], cves: [] }))
    })
    setMasscanHits(pendingHits)

    runScan(payload)
      .then((resp) => {
        setMasscanHits(resp.hits.map((h) => ({ ...h, status: 'open' })))
      })
      .catch((err) => {
        setError(err.message)
      })
  }

  return (
    <div className="card wide">
      <div className="card-header">
        <div>
          <p className="mono">ip space</p>
          <h3>Country Range Pull</h3>
        </div>
        <div className="pill">Async</div>
      </div>
      <div className={`config-layout grid ${hasResult ? 'grid-cols-result' : 'grid-cols-initial'}`}>
        <form className="form config-form" onSubmit={onSubmit}>
          <div className="field full">
            <label>Country (type to filter or pick)</label>
            <div className="combo">
              <input
                value={countryInput}
                onChange={(e) => {
                  const val = e.target.value
                  setCountryInput(val)
                  setCountry(extractCode(val))
                  setPickerOpen(true)
                }}
                onFocus={() => setPickerOpen(true)}
                onBlur={handleBlur}
                placeholder="Start typing a code or country name"
              />
              {pickerOpen && filteredCountries.length > 0 && (
                <div className="combo-list">
                  {filteredCountries.slice(0, 12).map((c) => (
                    <button
                      type="button"
                      key={c.code}
                      className="combo-item"
                      onMouseDown={(e) => e.preventDefault()}
                      onClick={() => commitCountry(c.code)}
                    >
                      <span className="mono">{c.code}</span>
                      <span>{c.name}</span>
                    </button>
                  ))}
                </div>
              )}
            </div>
            <p className="hint">
              {filteredCountries.length ? `${filteredCountries.length} matches` : 'No countries match your input'}
            </p>
          </div>

          <div className="row two-col">
            <div className="field">
              <label>RIRs</label>
              <div className="pill-row">
                {rirOptions.map((rir) => (
                  <button
                    type="button"
                    key={rir}
                    className={selectedRirs.includes(rir) ? 'pill selected' : 'pill'}
                    onClick={() => toggleRir(rir)}
                  >
                    {rir}
                  </button>
                ))}
              </div>
              <p className="hint">All selected by default.</p>
            </div>
          </div>

          <button type="submit" className="primary" disabled={loading}>
            {loading ? 'Pulling ranges...' : 'Run'}
          </button>
        </form>

        {hasResult && (
          <>
            <div className="ranges-pane">
              <div className="result-head">
                <div>
                  <p className="mono">
                    {result.country} - {result.country_name}
                  </p>
                  <h4>{result.total.toLocaleString()} unique ranges</h4>
                  <p className="hint">RIRs: {result.rirs.join(', ')}</p>
                </div>
              </div>

              <div className="field post-run">
                <label>Ports for masscan</label>
                <div className="inline-check">
                  <input
                    type="checkbox"
                    checked={allPorts}
                    onChange={(e) => {
                      setAllPorts(e.target.checked)
                      if (e.target.checked) clearPorts()
                    }}
                  />
                  <span>All ports (1-65535)</span>
                </div>
                {!allPorts && (
                  <>
                    <div className="combo with-action">
                      <input
                        value={portInput}
                        onChange={(e) => setPortInput(e.target.value)}
                        onKeyDown={handlePortKey}
                        onFocus={() => setPortPickerOpen(true)}
                        onBlur={() => setTimeout(() => setPortPickerOpen(false), 120)}
                        placeholder="Type port number and press Enter, e.g., 22"
                      />
                      <button type="button" className="ghost small" onClick={clearPorts}>
                        Clear
                      </button>
                      {portPickerOpen && filteredPorts.length > 0 && (
                        <div className="combo-list">
                          {filteredPorts.map((p) => (
                            <button
                              type="button"
                              key={p}
                              className="combo-item"
                              onMouseDown={(e) => e.preventDefault()}
                              onClick={() => {
                                addPort(p)
                                setPortInput('')
                              }}
                            >
                              <span className="mono">{p}</span>
                              <span>Common port</span>
                            </button>
                          ))}
                        </div>
                      )}
                    </div>
                    <div className="tag-row">
                      {selectedPorts.map((p) => (
                        <span key={p} className="tag">
                          {p}
                          <button type="button" onClick={() => setSelectedPorts(selectedPorts.filter((x) => x !== p))}>
                            x
                          </button>
                        </span>
                      ))}
                      {selectedPorts.length === 0 && <p className="hint">No ports selected yet.</p>}
                    </div>
                  </>
                )}
              </div>

              <div className="switch-row post-run">
                <label>
                  <input type="checkbox" checked={runMasscan} onChange={(e) => setRunMasscan(e.target.checked)} /> masscan
                </label>
                <label>
                  <input type="checkbox" checked={runCve} onChange={(e) => setRunCve(e.target.checked)} /> Detect CVE
                </label>
              </div>

              <div className="range-list">
                <div className="range-select-all">
                  <label>
                    <input
                      type="checkbox"
                      checked={selectedRanges.length === result.ranges.length && result.ranges.length > 0}
                      onChange={(e) => selectAllRanges(e.target.checked)}
                    />{' '}
                    Select all ranges
                  </label>
                </div>
                <p className="mono">IP Ranges</p>
                <div className="range-scroll">
                  {result.ranges.map((cidr) => (
                    <label key={cidr} className={selectedRanges.includes(cidr) ? 'range-item selected' : 'range-item'}>
                      <input
                        type="checkbox"
                        checked={selectedRanges.includes(cidr)}
                        onChange={() => toggleRange(cidr)}
                        onClick={(e) => e.stopPropagation()}
                      />
                      <button
                        type="button"
                        className="range-text"
                        onClick={() => setActiveRange(cidr)}
                      >
                        {cidr}
                      </button>
                    </label>
                  ))}
                </div>
              </div>
              <button
                type="button"
                className="primary"
                disabled={
                  !selectedRanges.length ||
                  (!runMasscan && !runCve) ||
                  (runMasscan && !allPorts && selectedPorts.length === 0)
                }
                onClick={onRunScans}
              >
                Run selected
              </button>
            </div>

            <div className="masscan-pane">
              <p className="mono">Masscan / CVE</p>
              <p className="hint">Selected range: <span className="mono">{selectedRange}</span></p>
              <div className="ip-list">
                {sampleIps.map((ip) => {
                  const hit = selectedRangeIps.find((h) => h.ip === ip)
                  const hasPorts = hit && hit.status === 'open' && hit.ports && hit.ports.length
                  const statusText = hit
                    ? hit.status === 'open'
                      ? hit.ports.join(', ')
                      : 'scanning'
                    : runMasscan
                      ? 'scanning'
                      : 'waiting'
                  return (
                    <button
                      key={ip}
                      className="ip-item"
                      onClick={() => {
                        if (hit) {
                          const url = `/ip/${encodeURIComponent(hit.ip)}`
                          window.open(url, '_blank')
                        }
                      }}
                    >
                      <span className={`status-dot ${hasPorts ? 'open' : 'pending'}`} />
                      <span className="mono">{ip}</span>
                      <span className="ports">{statusText}</span>
                    </button>
                  )
                })}
              </div>
              {!runMasscan && <p className="hint">Enable masscan to populate open ports automatically.</p>}
            </div>
          </>
        )}
      </div>

      {error && <p className="error">{error}</p>}
    </div>
  )
}
