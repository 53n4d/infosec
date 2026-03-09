import { NavLink } from 'react-router-dom'
import { RiRadarLine, RiMapPinRangeLine } from 'react-icons/ri'
import { TbShieldBolt } from 'react-icons/tb'
import { MdOutlineFiberManualRecord } from 'react-icons/md'

export default function NavBar() {
  return (
    <nav className="navbar">
      <div className="nav-inner">
        {/* Brand */}
        <NavLink to="/" end className="nav-brand">
          <span className="nav-brand-icon" aria-hidden>
            <TbShieldBolt size={15} />
          </span>
          <span className="nav-brand-text">X<span>SEVERITY</span></span>
        </NavLink>

        <span className="nav-divider" aria-hidden />

        {/* Navigation links */}
        <NavLink
          to="/"
          end
          className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}
        >
          <span className="nav-icon"><RiMapPinRangeLine aria-hidden /></span>
          Range Pull
        </NavLink>

        <NavLink
          to="/scan"
          className={({ isActive }) => `nav-link${isActive ? ' active' : ''}`}
        >
          <span className="nav-icon"><RiRadarLine aria-hidden /></span>
          Scan Console
        </NavLink>

        {/* Status indicator */}
        <div className="nav-status" aria-label="System status: online">
          <span className="nav-status-dot" aria-hidden />
          SYS ONLINE
        </div>
      </div>
    </nav>
  )
}