import { BrowserRouter, Routes, Route } from 'react-router-dom'
import { useState } from 'react'
import NavBar from './components/NavBar'
import Hero from './components/Hero'
import RangeLookup from './components/RangeLookup'
import ScanDashboard from './components/ScanDashboard'
import ScanConsole from './components/ScanConsole'
import IpDetail from './components/IpDetail'

export default function App() {
  // Lifted RangeLookup state — persists across navigation
  const [rangeResult, setRangeResult] = useState(null)
  const [selectedRanges, setSelectedRanges] = useState([])

  return (
    <BrowserRouter>
      <NavBar />
      <main className="content">
        <Routes>
          <Route path="/" element={
            <>
              <Hero />
              <RangeLookup
                rangeResult={rangeResult}
                setRangeResult={setRangeResult}
                selectedRanges={selectedRanges}
                setSelectedRanges={setSelectedRanges}
              />
            </>
          } />
          <Route path="/scan" element={<ScanDashboard />} />
          <Route path="/scan/new" element={<ScanConsole />} />
          <Route path="/scan/:jobId" element={<ScanConsole />} />
          <Route path="/ip/:ip" element={<IpDetail />} />
        </Routes>
      </main>
    </BrowserRouter>
  )
}