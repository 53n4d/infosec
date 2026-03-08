import { useState } from 'react'
import { fetchCves } from '../api'

export default function CVEProbe() {
  const [software, setSoftware] = useState('nginx')
  const [version, setVersion] = useState('1.24')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [results, setResults] = useState([])

  const onSubmit = async (e) => {
    e.preventDefault()
    setLoading(true)
    setError('')
    try {
      const data = await fetchCves(software, version)
      setResults(data.results)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="card">
      <div className="card-header">
        <div>
          <p className="mono">nvd</p>
          <h3>CVE Quick Probe</h3>
        </div>
        <div className="pill">Lookup</div>
      </div>
      <form className="form" onSubmit={onSubmit}>
        <div className="field two-col">
          <div>
            <label>Software / product</label>
            <input value={software} onChange={(e) => setSoftware(e.target.value)} placeholder="nginx" />
          </div>
          <div>
            <label>Version</label>
            <input value={version} onChange={(e) => setVersion(e.target.value)} placeholder="1.24" />
          </div>
        </div>
        <button type="submit" className="primary" disabled={loading || !software}>
          {loading ? 'Querying NVD...' : 'Search CVEs'}
        </button>
      </form>

      {error && <p className="error">{error}</p>}

      {results.length > 0 && (
        <div className="result">
          <div className="result-head">
            <div>
              <p className="mono">Top {results.length} CVEs</p>
              <h4>{software} {version}</h4>
            </div>
          </div>
          <div className="cve-list">
            {results.map((item) => (
              <div key={item.id} className="cve-item">
                <div className="cve-head">
                  <span className="badge strong">{item.id}</span>
                  <span className={`score ${item.severity?.toLowerCase()}`}>CVSS {item.score} - {item.severity}</span>
                </div>
                <p>{item.desc}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
