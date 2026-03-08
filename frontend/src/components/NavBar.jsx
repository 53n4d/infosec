import { NavLink } from 'react-router-dom'
import { FiMap, FiCrosshair } from 'react-icons/fi'

export default function NavBar() {
  return (
    <nav className="navbar">
      <div className="nav-inner">
        <NavLink to="/" end className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}>
          <span className="nav-icon"><FiMap aria-hidden /></span> Range Pull
        </NavLink>
        <NavLink to="/scan" className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}>
          <span className="nav-icon"><FiCrosshair aria-hidden /></span> Scan Console
        </NavLink>
      </div>
    </nav>
  )
}
