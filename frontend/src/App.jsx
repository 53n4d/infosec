import Hero from './components/Hero'
import RangeLookup from './components/RangeLookup'
import StatGrid from './components/StatGrid'

export default function App() {
  return (
    <div className="page-shell">
      <div className="grid-overlay" aria-hidden />
      <Hero />
      <main className="content">
        <section className="panel-stack">
          <RangeLookup />
        </section>
        <StatGrid />
      </main>
    </div>
  )
}
