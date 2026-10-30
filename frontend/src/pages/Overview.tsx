import { Link } from "react-router-dom"

const steps = [
  { n: "1", title: "Ingest events", body: "Host telemetry: process, file, network" },
  { n: "2", title: "Score", body: "Ensemble model + rules baselines" },
  { n: "3", title: "Explain", body: "Feature contributions → MITRE techniques" },
  { n: "4", title: "Tier", body: "Auto-contain candidate / analyst review / watch" },
  { n: "5", title: "Feedback", body: "Analyst label with provenance → retrain carefully" }
]

export default function Overview() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-semibold text-ink-100">Overview</h1>
        <p className="text-sm text-ink-400 mt-1">
          CYB SOC is a ransomware detection pipeline with evaluation hygiene — not a magic AI box.
        </p>
      </div>

      <div className="bg-surface-800 border border-surface-700 rounded-md p-4">
        <div className="text-sm font-medium mb-3">How an alert is produced</div>
        <div className="grid grid-cols-5 gap-2">
          {steps.map((s) => (
            <div key={s.n} className="bg-surface-900 border border-surface-700 rounded p-3">
              <div className="text-xs text-accent font-semibold mb-1">Step {s.n}</div>
              <div className="text-sm text-ink-100">{s.title}</div>
              <div className="text-xs text-ink-400 mt-1">{s.body}</div>
            </div>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-3 gap-4">
        <Link to="/demo" className="bg-surface-800 border border-accent/40 rounded-md p-4 hover:bg-surface-700/50">
          <div className="text-sm font-medium text-ink-100">Live demo</div>
          <div className="text-xs text-ink-400 mt-1">Score ransomware vs benign vs lateral scenarios on the real API</div>
        </Link>
        <Link to="/models" className="bg-surface-800 border border-surface-700 rounded-md p-4 hover:bg-surface-700/50">
          <div className="text-sm font-medium text-ink-100">Models & metrics</div>
          <div className="text-xs text-ink-400 mt-1">Leakage check, PR-AUC, poisoning, CLEAR known/unknown</div>
        </Link>
        <Link to="/alerts" className="bg-surface-800 border border-surface-700 rounded-md p-4 hover:bg-surface-700/50">
          <div className="text-sm font-medium text-ink-100">Alerts</div>
          <div className="text-xs text-ink-400 mt-1">Example queue with severity and techniques</div>
        </Link>
      </div>

      <div className="grid grid-cols-4 gap-4">
        <div className="bg-surface-800 border border-surface-700 rounded-md p-4">
          <div className="text-xs text-ink-400">What this proves</div>
          <div className="text-sm mt-1 text-ink-200">Pipeline works end-to-end with measurable failure modes</div>
        </div>
        <div className="bg-surface-800 border border-surface-700 rounded-md p-4">
          <div className="text-xs text-ink-400">What this is not</div>
          <div className="text-sm mt-1 text-ink-200">A production XDR or claim of real-world 99% detection</div>
        </div>
        <div className="bg-surface-800 border border-surface-700 rounded-md p-4">
          <div className="text-xs text-ink-400">Credibility signals</div>
          <div className="text-sm mt-1 text-ink-200">Leakage pass · poisoning drop · gated containment</div>
        </div>
        <div className="bg-surface-800 border border-surface-700 rounded-md p-4">
          <div className="text-xs text-ink-400">Start here</div>
          <div className="text-sm mt-1 text-ink-200">Open Live demo and score the ransomware scenario</div>
        </div>
      </div>
    </div>
  )
}
