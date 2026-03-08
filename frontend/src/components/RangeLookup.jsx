import { useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { fetchCountries, fetchRanges } from '../api'

export default function RangeLookup() {
  const navigate = useNavigate()
  const [countries, setCountries] = useState([])
  const [country, setCountry] = useState('')
  const [countryInput, setCountryInput] = useState('')
  const [pickerOpen, setPickerOpen] = useState(false)
  const rirOptions = useMemo(() => ['RIPE', 'ARIN', 'APNIC', 'LACNIC', 'AFRINIC'], [])
  const [selectedRirs, setSelectedRirs] = useState(rirOptions)
  const [force, setForce] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState(null)
  const [copied, setCopied] = useState(false)
  const [selectedRanges, setSelectedRanges] = useState([])

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

  useEffect(() => { setSelectedRirs(rirOptions) }, [rirOptions])

  const filteredCountries = useMemo(() => {
    const term = countryInput.toLowerCase()
    if (!term.trim()) return countries
    return countries.filter(
      (c) => c.code.toLowerCase().includes(term) || c.name.toLowerCase().includes(term)
    )
  }, [countries, countryInput])

  const toggleRir = (name) =>
    setSelectedRirs((prev) =>
      prev.includes(name) ? prev.filter((r) => r !== name) : [...prev, name]
    )

  const commitCountry = (code) => {
    const found = countries.find((c) => c.code === code)
    setCountry(code)
    setCountryInput(found ? `${found.code} - ${found.name}` : code)
    setPickerOpen(false)
  }

  const handleBlur = () => {
    setTimeout(() => setPickerOpen(false), 120)
    if (!country && filteredCountries.length) commitCountry(filteredCountries[0].code)
  }

  const onSubmit = async (e) => {
    e.preventDefault()
    if (!country) return
    setError('')
    setLoading(true)
    setResult(null)
    setSelectedRanges([])
    try {
      const data = await fetchRanges({ country, rirs: selectedRirs, force })
      setResult(data)
      setSelectedRanges(data.ranges) // select all by default
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const allChecked = result && selectedRanges.length === result.ranges.length
  const someChecked = selectedRanges.length > 0 && !allChecked

  const toggleAll = () => {
    if (allChecked) setSelectedRanges([])
    else setSelectedRanges(result.ranges)
  }

  const toggleRange = (cidr) =>
    setSelectedRanges((prev) =>
      prev.includes(cidr) ? prev.filter((r) => r !== cidr) : [...prev, cidr]
    )

  const copySelected = () => {
    const text = (selectedRanges.length ? selectedRanges : result?.ranges ?? []).join('\n')
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    })
  }

  const goScan = () => {
    const toSend = selectedRanges.length ? selectedRanges : result?.ranges ?? []
    navigate('/scan', { state: { ranges: toSend.join('\n') } })
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

      <div className={`config-layout grid ${result ? 'grid-cols-result' : 'grid-cols-initial'}`}>

        {/* Config form */}
        <form className="form config-form" onSubmit={onSubmit}>
          <div className="field full">
            <label>Country (type to filter or pick)</label>
            <div className="combo">
              <input
                value={countryInput}
                onChange={(e) => { setCountryInput(e.target.value); setCountry(extractCode(e.target.value)); setPickerOpen(true) }}
                onFocus={() => setPickerOpen(true)}
                onBlur={handleBlur}
                placeholder="Start typing a code or country name"
              />
              {pickerOpen && filteredCountries.length > 0 && (
                <div className="combo-list">
                  {filteredCountries.slice(0, 12).map((c) => (
                    <button type="button" key={c.code} className="combo-item"
                      onMouseDown={(e) => e.preventDefault()} onClick={() => commitCountry(c.code)}>
                      <span className="mono">{c.code}</span><span>{c.name}</span>
                    </button>
                  ))}
                </div>
              )}
            </div>
            <p className="hint">
              {filteredCountries.length ? `${filteredCountries.length} matches` : 'No countries match your input'}
            </p>
          </div>

          <div className="field">
            <label>RIRs</label>
            <div className="pill-row">
              {rirOptions.map((rir) => (
                <button type="button" key={rir}
                  className={selectedRirs.includes(rir) ? 'pill selected' : 'pill'}
                  onClick={() => toggleRir(rir)}>{rir}</button>
              ))}
            </div>
            <p className="hint">All selected by default.</p>
          </div>

          <div className="switch-row">
            <label>
              <input type="checkbox" checked={force} onChange={(e) => setForce(e.target.checked)} />
              Force refresh cache
            </label>
          </div>

          <button type="submit" className="primary" disabled={loading}>
            {loading ? 'Pulling ranges...' : 'Pull Ranges'}
          </button>
        </form>

        {/* Results pane */}
        {result && (
          <div className="ranges-pane">
            <div className="result-head">
              <div>
                <p className="mono">{result.country} — {result.country_name}</p>
                <h4>{result.total.toLocaleString()} unique ranges</h4>
                <p className="hint">RIRs: {result.rirs.join(', ')}</p>
              </div>
              <div className="result-actions">
                <button type="button" className="ghost small" onClick={copySelected}>
                  {copied ? '✓ Copied' : `Copy${selectedRanges.length ? ` (${selectedRanges.length})` : ''}`}
                </button>
                <button
                  type="button"
                  className="primary small"
                  onClick={goScan}
                  disabled={selectedRanges.length === 0}
                >
                  {selectedRanges.length > 0 ? `Scan (${selectedRanges.length}) →` : 'Select ranges'}
                </button>
              </div>
            </div>

            {/* Select-all bar */}
            <div className="range-select-bar">
              <label className="range-select-all-label">
                <input
                  type="checkbox"
                  checked={allChecked}
                  ref={(el) => { if (el) el.indeterminate = someChecked }}
                  onChange={toggleAll}
                />
                <span>
                  {allChecked
                    ? `All ${result.total} selected`
                    : someChecked
                      ? `${selectedRanges.length} of ${result.total} selected`
                      : 'Select all'}
                </span>
              </label>
              {someChecked && (
                <button type="button" className="ghost small" onClick={() => setSelectedRanges(result.ranges)}>
                  Select all {result.total}
                </button>
              )}
            </div>

            <div className="range-list">
              <div className="range-scroll">
                {result.ranges.map((cidr) => {
                  const checked = selectedRanges.includes(cidr)
                  return (
                    <label key={cidr} className={`range-item-check ${checked ? 'checked' : ''}`}>
                      <input
                        type="checkbox"
                        checked={checked}
                        onChange={() => toggleRange(cidr)}
                      />
                      <span className="mono range-text">{cidr}</span>
                      <a
                        href={`/ip/${encodeURIComponent(cidr.split('/')[0])}`}
                        target="_blank"
                        rel="noreferrer"
                        className="range-detail-link"
                        onClick={(e) => e.stopPropagation()}
                        title="IP detail"
                      >↗</a>
                    </label>
                  )
                })}
              </div>
            </div>

            {result.masscan_hint && (
              <div className="masscan-hint-box">
                <p className="mono hint-label">masscan command</p>
                <pre className="hint-pre">{result.masscan_hint}</pre>
              </div>
            )}
          </div>
        )}
      </div>

      {error && <p className="error">{error}</p>}
    </div>
  )
}