import { useEffect, useState } from 'react'
import { fetchPorts, health } from '../api'

export default function StatGrid() {
  const [status, setStatus] = useState(null)
  const [ports, setPorts] = useState({ cve_probe_ports: [], masscan_ports: [] })

  useEffect(() => {
    health().then(setStatus).catch(() => {})
    fetchPorts().then(setPorts).catch(() => {})
  }, [])

  const tiles = [
    {
      title: 'API status',
      value: status ? status.status : '-',
      sub: status ? status.timestamp : 'waiting...',
    },
    {
      title: 'RIR coverage',
      value: status ? status.available_rirs : '-',
      sub: 'RIPE / ARIN / APNIC / LACNIC / AFRINIC',
    },
    {
      title: 'CVE probe ports',
      value: ports.cve_probe_ports.length,
      sub: ports.cve_probe_ports.slice(0, 10).join(', ') || 'loading',
    },
    {
      title: 'Masscan preset',
      value: `${ports.masscan_ports.length || '-'} ports`,
      sub: 'Opinionated wide-scan list',
    },
  ]

  return (
    <section className="stat-grid">
      {tiles.map((tile) => (
        <div key={tile.title} className="stat-card">
          <p className="mono">{tile.title}</p>
          <h3>{tile.value}</h3>
          <p className="hint">{tile.sub}</p>
        </div>
      ))}
      <div className="stat-card full">
        <p className="mono">Roadmap</p>
        <h3>Upcoming drops</h3>
        <ul className="roadmap">
          <li>Stream masscan hits into live CVE queue</li>
          <li>Service fingerprint heatmaps per country</li>
          <li>API tokens and audit logging</li>
          <li>Export to JSONL / Redis queue</li>
        </ul>
      </div>
    </section>
  )
}