import { Routes, Route, NavLink } from "react-router-dom"
import Overview from "./pages/Overview"
import Alerts from "./pages/Alerts"
import AlertDetail from "./pages/AlertDetail"
import Models from "./pages/Models"
import Hunt from "./pages/Hunt"
import Feedback from "./pages/Feedback"
import LiveDemo from "./pages/LiveDemo"

const nav = [
  { to: "/", label: "Overview" },
  { to: "/demo", label: "Live demo" },
  { to: "/alerts", label: "Alerts" },
  { to: "/hunt", label: "Hunt" },
  { to: "/models", label: "Models" },
  { to: "/feedback", label: "Feedback" }
]

export default function App() {
  return (
    <div className="min-h-screen flex bg-surface-950 font-sans">
      <aside className="w-56 border-r border-surface-700 bg-surface-900 flex flex-col">
        <div className="px-4 py-5 border-b border-surface-700">
          <div className="text-sm font-semibold tracking-wide text-ink-100">CYB SOC</div>
          <div className="text-xs text-ink-400 mt-0.5">Detection pipeline</div>
        </div>
        <nav className="flex-1 py-3">
          {nav.map((n) => (
            <NavLink
              key={n.to}
              to={n.to}
              end={n.to === "/"}
              className={({ isActive }) =>
                `block px-4 py-2.5 text-sm transition-colors ${
                  isActive
                    ? "bg-surface-700/80 text-ink-100 border-l-2 border-accent"
                    : "text-ink-300 hover:bg-surface-800 hover:text-ink-100 border-l-2 border-transparent"
                }`
              }
            >
              {n.label}
            </NavLink>
          ))}
        </nav>
        <div className="px-4 py-3 border-t border-surface-700 text-xs text-ink-400 space-y-1">
          <div className="text-ink-300">Connected: Local API (v1.0)</div>
          <div>Auth: Dev Session</div>
        </div>
      </aside>
      <main className="flex-1 overflow-auto">
        <header className="h-12 border-b border-surface-700 bg-surface-900 flex items-center justify-between px-6">
          <div className="text-sm text-ink-300 font-medium tracking-wide">
            Score → Explain → Tier → Feedback
          </div>
          <div className="flex items-center gap-2 text-xs text-ink-400">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
            Lab mode
          </div>
        </header>
        <div className="p-6">
          <Routes>
            <Route path="/" element={<Overview />} />
            <Route path="/demo" element={<LiveDemo />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/alerts/:id" element={<AlertDetail />} />
            <Route path="/hunt" element={<Hunt />} />
            <Route path="/models" element={<Models />} />
            <Route path="/feedback" element={<Feedback />} />
          </Routes>
        </div>
      </main>
    </div>
  )
}
