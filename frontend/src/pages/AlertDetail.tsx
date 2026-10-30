import { useState } from "react"
import { Link, useParams } from "react-router-dom"

const timeline = [
  { t: "14:19:44", type: "process_spawn", detail: "procdump.exe -ma lsass.exe" },
  { t: "14:20:11", type: "process_spawn", detail: "vssadmin delete shadows /all /quiet" },
  { t: "14:21:03", type: "file_rename", detail: "report.docx → report.docx.locked" },
  { t: "14:21:48", type: "file_rename", detail: "budget.xlsx → budget.xlsx.ryuk" },
  { t: "14:22:08", type: "alert", detail: "Alert raised · score 94" }
]

const contribs = [
  { feature: "encrypt_ext_hits", contribution: 0.31 },
  { feature: "shadow_delete_hits", contribution: 0.24 },
  { feature: "entropy_spike_count", contribution: 0.18 },
  { feature: "lsass_hits", contribution: 0.12 }
]

export default function AlertDetail() {
  const { id } = useParams()
  const [gate, setGate] = useState("")

  function requestContain() {
    setGate("BLOCKED — Isolate host requires Tier-2 analyst approval. Destructive actions are never auto-executed by the model or LLM.")
  }

  const maxAbs = Math.max(...contribs.map((c) => Math.abs(c.contribution)), 0.01)

  return (
    <div className="space-y-5 max-w-4xl">
      <Link to="/alerts" className="text-sm text-ink-400 hover:text-ink-200">
        ← Back to alerts
      </Link>

      <div>
        <div className="flex items-center gap-3 flex-wrap">
          <h1 className="text-lg font-semibold">Alert {id}</h1>
          <span className="text-xs px-2 py-0.5 rounded bg-red-950/80 text-red-300 border border-red-800 font-medium">
            CRITICAL
          </span>
          <span className="text-sm text-ink-300 font-mono">Score 94</span>
        </div>
        <div className="mt-2 text-sm text-ink-400 flex flex-wrap gap-6">
          <span>Host: <span className="text-ink-200 font-mono">dc-prod-01</span></span>
          <span>User: <span className="text-ink-200 font-mono">svc-backup</span></span>
          <span>First seen: <span className="text-ink-200 font-mono">14:19:44</span></span>
        </div>
      </div>

      <div className="bg-surface-800 border border-surface-700 rounded-md p-4">
        <div className="text-sm font-medium mb-2">Why this was flagged</div>
        <p className="text-sm text-ink-300 leading-relaxed mb-3">
          High velocity file renames with ransomware extensions + shadow copy deletion + LSASS access.
          Strong match to T1486 (Data Encrypted for Impact).
        </p>
        <div className="space-y-2">
          {contribs.map((c) => {
            const w = (Math.abs(c.contribution) / maxAbs) * 100
            return (
              <div key={c.feature}>
                <div className="flex justify-between text-xs mb-0.5">
                  <span className="font-mono text-ink-300">{c.feature}</span>
                  <span className="text-red-300">+{c.contribution.toFixed(2)}</span>
                </div>
                <div className="h-1.5 bg-surface-900 rounded overflow-hidden">
                  <div className="h-full bg-red-700/80 rounded" style={{ width: `${w}%` }} />
                </div>
              </div>
            )
          })}
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div className="bg-surface-800 border border-surface-700 rounded-md p-4">
          <div className="text-sm font-medium mb-3">Timeline</div>
          <div className="space-y-2.5">
            {timeline.map((e) => (
              <div key={e.t} className="flex gap-3 text-sm">
                <div className="text-ink-400 w-16 shrink-0 font-mono text-xs">{e.t}</div>
                <div>
                  <div className="text-ink-400 text-xs font-mono">{e.type}</div>
                  <div className="text-ink-100 font-mono text-xs">{e.detail}</div>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="space-y-4">
          <div className="bg-surface-800 border border-surface-700 rounded-md p-4">
            <div className="text-sm font-medium mb-2">MITRE techniques</div>
            <ul className="text-sm space-y-1.5 text-ink-300 font-mono">
              <li>T1486 · Impact</li>
              <li>T1003 · Credential Access</li>
              <li>T1070 · Defense Evasion</li>
            </ul>
          </div>
          <div className="bg-surface-800 border border-surface-700 rounded-md p-4">
            <div className="text-sm font-medium mb-2">Suggested containment</div>
            <ul className="text-sm space-y-1.5 text-ink-300">
              <li>Isolate host dc-prod-01</li>
              <li>Disable account svc-backup</li>
              <li>Block known ransomware extensions</li>
            </ul>
            <button
              onClick={requestContain}
              className="mt-3 text-xs px-3 py-1.5 rounded border border-red-800 text-red-300 hover:bg-red-950/50"
            >
              Auto-execute containment
            </button>
            {gate && (
              <div className="mt-3 text-xs bg-red-950/50 border border-red-700 rounded p-2 text-red-200">
                <span className="font-semibold">[BLOCKED]</span> {gate}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
