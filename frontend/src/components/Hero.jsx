export default function Hero() {
  return (
    <header className="hero">
      <div>
        <p className="eyebrow">asynchronous recon - multi-rir - cve aware</p>
        <h1>XSEVERITY Recon Console</h1>
        <p className="lede">
          Pull IPv4 allocations per country in real time, craft masscan runs, and pivot into CVE lookups - all
          from a slick, operator-first UI.
        </p>
        <div className="chip-row">
          <span className="chip">Async RIR fetch</span>
          <span className="chip">Neon masscan hinting</span>
          <span className="chip">NVD quick search</span>
        </div>
      </div>
      <div className="hero-card">
        <p className="mono">live</p>
        <h3>Recon Ready</h3>
        <p>Deploy the API, point the UI, and start slicing address space by country.</p>
      </div>
    </header>
  )
}