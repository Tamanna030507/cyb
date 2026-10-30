import { useState } from "react"
import { scoreEvents } from "../api/client"

const PRESETS = {
  ransomware: {
    label: "Ransomware-like host",
    host_id: "dc-prod-01",
    user_id: "svc-backup",
    events: [
      { event_type: "process_spawn", process_name: "procdump.exe", command_line: "procdump.exe -ma lsass.exe C:\\temp\\lsass.dmp" },
      { event_type: "process_spawn", process_name: "vssadmin.exe", command_line: "vssadmin delete shadows /all /quiet" },
      { event_type: "file_rename", path: "C:\\Users\\admin\\report.docx", new_path: "C:\\Users\\admin\\report.docx.locked" },
      { event_type: "file_rename", path: "C:\\Users\\admin\\budget.xlsx", new_path: "C:\\Users\\admin\\budget.xlsx.ryuk" },
      { event_type: "process_spawn", process_name: "wevtutil.exe", command_line: "wevtutil.exe cl Security" }
    ]
  },
  benign: {
    label: "Normal user host",
    host_id: "laptop-22",
    user_id: "alice",
    events: [
      { event_type: "process_spawn", process_name: "chrome.exe", command_line: "chrome.exe" },
      { event_type: "file_open", path: "C:\\Users\\alice\\Documents\\notes.docx" },
      { event_type: "network_flow", destination: "10.0.0.12", bytes_sent: 1200, bytes_recv: 8000 },
      { event_type: "process_spawn", process_name: "outlook.exe", command_line: "outlook.exe" }
    ]
  },
  lateral: {
    label: "Lateral movement",
    host_id: "workstn-42",
    user_id: "svc-admin",
    events: [
      { event_type: "process_spawn", process_name: "psexec.exe", command_line: "psexec \\\\dc-02 cmd.exe" },
      { event_type: "process_spawn", process_name: "net.exe", command_line: "net user /domain" },
      { event_type: "process_spawn", process_name: "whoami.exe", command_line: "whoami /all" }
    ]
  }
}

function sevBadge(sev: string) {
  const s = (sev || "").toLowerCase()
  if (s === "critical") return "bg-red-950/80 text-red-300 border border-red-800"
  if (s === "high") return "bg-orange-950/80 text-orange-300 border border-orange-800"
  if (s === "medium") return "bg-amber-950/70 text-amber-200 border border-amber-800"
  return "bg-slate-800 text-slate-300 border border-slate-600"
}

export default function LiveDemo() {
  const [preset, setPreset] = useState<keyof typeof PRESETS>("ransomware")
  const [result, setResult] = useState<any>(null)
  const [err, setErr] = useState("")
  const [busy, setBusy] = useState(false)
  const [gateMsg, setGateMsg] = useState("")

  async function run() {
    setBusy(true)
    setErr("")
    setResult(null)
    setGateMsg("")
    await new Promise((r) => setTimeout(r, 320))
    try {
      const p = PRESETS[preset]
      const r = await scoreEvents({
        host_id: p.host_id,
        user_id: p.user_id,
        events: p.events
      })
      setResult(r)
    } catch (e: any) {
      setErr(e.message || String(e))
    } finally {
      setBusy(false)
    }
  }

  function tryContain() {
    if (!result) return
    const score = result.score ?? 0
    if (score >= 0.85) {
      setGateMsg("BLOCKED — Isolate host requires Tier-2 analyst approval. Destructive actions are never auto-executed.")
    } else {
      setGateMsg("Queued for analyst review — no auto-contain at this tier.")
    }
  }

  const contribs = result?.feature_contributions || []
  const maxAbs = Math.max(...contribs.map((c: any) => Math.abs(c.contribution || 0)), 0.01)

  return (
    <div className="space-y-6 max-w-4xl">
      <div>
        <h1 className="text-lg font-semibold">Live detection demo</h1>
        <p className="text-sm text-ink-400 mt-1">
          Pick a scenario → score against the trained model → see severity, tier, and feature contributions
        </p>
      </div>

      <div className="bg-surface-800 border border-surface-700 rounded-md p-4 space-y-4">
        <div className="text-sm font-medium">Scenario</div>
        <div className="flex flex-wrap gap-2">
          {(Object.keys(PRESETS) as Array<keyof typeof PRESETS>).map((k) => (
            <button
              key={k}
              onClick={() => { setPreset(k); setResult(null); setGateMsg("") }}
              className={`text-sm px-3 py-1.5 rounded border ${
                preset === k
                  ? "bg-accent/20 border-accent text-ink-100"
                  : "bg-surface-900 border-surface-700 text-ink-300 hover:border-surface-600"
              }`}
            >
              {PRESETS[k].label}
            </button>
          ))}
        </div>

        <div className="text-xs text-ink-400">
          Host: <span className="text-ink-200 font-mono">{PRESETS[preset].host_id}</span>
          {" · "}
          Events: <span className="text-ink-200 font-mono">{PRESETS[preset].events.length}</span>
        </div>

        <pre className="text-xs bg-surface-900 border border-surface-700 rounded p-3 overflow-x-auto text-ink-300 max-h-40 font-mono leading-relaxed">
{JSON.stringify(PRESETS[preset].events, null, 2)}
        </pre>

        <button
          onClick={run}
          disabled={busy}
          className="text-sm px-4 py-2 bg-accent/90 hover:bg-accent rounded text-white disabled:opacity-50 inline-flex items-center gap-2"
        >
          {busy && (
            <span className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
          )}
          {busy ? "Scoring telemetry…" : "Score this host"}
        </button>
      </div>

      {err && (
        <div className="bg-red-950/40 border border-red-800 rounded-md p-3 text-sm text-red-300">
          {err}
          <div className="text-xs mt-1 text-ink-400">Start API on :8001 · header X-Api-Key: dev-key-change-me</div>
        </div>
      )}

      {result && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div className="bg-surface-800 border border-surface-700 rounded-md p-4 space-y-3">
              <div className="text-sm font-medium">Result</div>
              <div className="flex items-end gap-3">
                <div className="text-3xl font-semibold font-mono tabular-nums">
                  {((result.score || 0) * 100).toFixed(1)}
                </div>
                <span className={`text-xs px-2 py-0.5 rounded mb-1 ${sevBadge(result.severity)}`}>
                  {(result.severity || "low").toUpperCase()}
                </span>
              </div>
              <div className="text-sm space-y-1">
                <div className="flex justify-between">
                  <span className="text-ink-400">Tier</span>
                  <span className="font-mono text-ink-100">{result.tier?.tier || "—"}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-ink-400">Action</span>
                  <span className="font-mono text-ink-100 text-right max-w-[60%]">{result.tier?.action || "—"}</span>
                </div>
                <div className="flex justify-between text-xs text-ink-400">
                  <span>Latency</span>
                  <span className="font-mono">{result.latency_ms} ms</span>
                </div>
              </div>
              <button
                onClick={tryContain}
                className="mt-2 text-xs px-3 py-1.5 rounded border border-red-800/80 text-red-300 hover:bg-red-950/50"
              >
                Request auto-containment
              </button>
            </div>

            <div className="bg-surface-800 border border-surface-700 rounded-md p-4 space-y-3">
              <div className="text-sm font-medium">Why it was flagged</div>
              <p className="text-sm text-ink-300 leading-relaxed">
                {result.explanation || "No strong feature contributions above threshold."}
              </p>
              <div className="space-y-2 pt-1">
                {contribs.slice(0, 6).map((c: any) => {
                  const w = Math.min(100, (Math.abs(c.contribution) / maxAbs) * 100)
                  const pos = c.contribution >= 0
                  return (
                    <div key={c.feature}>
                      <div className="flex justify-between text-xs mb-0.5">
                        <span className="font-mono text-ink-300">{c.feature}</span>
                        <span className={pos ? "text-red-300" : "text-emerald-400"}>
                          {pos ? "+" : ""}{Number(c.contribution).toFixed(3)}
                        </span>
                      </div>
                      <div className="h-1.5 bg-surface-900 rounded overflow-hidden">
                        <div
                          className={`h-full rounded ${pos ? "bg-red-700/80" : "bg-emerald-700/70"}`}
                          style={{ width: `${w}%` }}
                        />
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>
          </div>

          {gateMsg && (
            <div className="bg-red-950/50 border border-red-700 rounded-md p-3 text-sm text-red-200">
              <span className="font-semibold">[BLOCKED]</span> {gateMsg}
            </div>
          )}
        </div>
      )}

      <div className="bg-surface-800 border border-surface-700 rounded-md p-4 text-sm text-ink-400 leading-relaxed">
        <span className="text-ink-200 font-medium">Pipeline: </span>
        host telemetry → feature extraction → ensemble score → severity tier → contributions.
        Containment is gated; destructive actions require human approval.
      </div>
    </div>
  )
}
