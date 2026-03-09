import { TbWorldSearch, TbRadar, TbShieldBolt } from 'react-icons/tb'
import { RiTerminalBoxLine } from 'react-icons/ri'
import { MdOutlineFiberManualRecord } from 'react-icons/md'

export default function Hero() {
  return (
    <header className="hero">
      <div>
        <div className="eyebrow">
          <span className="eyebrow-dot" aria-hidden />
          asynchronous recon &nbsp;·&nbsp; multi-rir &nbsp;·&nbsp; cve aware
        </div>

        <h1>
          XSEVERITY<br />
          <span className="accent">Recon Console</span>
        </h1>

        <p className="lede">
          Pull IPv4 allocations per country in real time, craft masscan runs,
          and pivot into CVE lookups — all from a precision, operator-first interface.
        </p>

        <div className="chip-row">
          <span className="chip">
            <TbWorldSearch size={11} aria-hidden />
            Async RIR Fetch
          </span>
          <span className="chip">
            <RiTerminalBoxLine size={11} aria-hidden />
            Masscan Hinting
          </span>
          <span className="chip">
            <TbShieldBolt size={11} aria-hidden />
            NVD Quick Search
          </span>
          <span className="chip">
            <TbRadar size={11} aria-hidden />
            Community Intel
          </span>
        </div>
      </div>

      {/* Status card */}
      <div className="hero-card" aria-label="System status">
        <div className="hero-card-status">
          <MdOutlineFiberManualRecord size={8} style={{ color: 'var(--low)' }} aria-hidden />
          RECON READY
        </div>
        <h3>Operator Console</h3>
        <p>Deploy the API, point the UI, and begin slicing address space by country and RIR.</p>
        <div className="hero-card-grid">
          <div className="hero-card-metric">
            <span className="hero-card-metric-val">5</span>
            <span className="hero-card-metric-label">RIRs</span>
          </div>
          <div className="hero-card-metric">
            <span className="hero-card-metric-val">249</span>
            <span className="hero-card-metric-label">Countries</span>
          </div>
          <div className="hero-card-metric">
            <span className="hero-card-metric-val">CVE</span>
            <span className="hero-card-metric-label">Aware</span>
          </div>
          <div className="hero-card-metric">
            <span className="hero-card-metric-val">Live</span>
            <span className="hero-card-metric-label">Stream</span>
          </div>
        </div>
      </div>
    </header>
  )
}