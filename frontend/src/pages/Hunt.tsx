import { useState } from "react"
import { validateSpl } from "../api/client"

export default function Hunt() {
  const [query, setQuery] = useState(
    `search earliest=-30m index=main sourcetype=WinEventLog:Security
(EventCode=4688 OR EventCode=4663)
| where like(CommandLine, "%vssadmin%") OR like(CommandLine, "%lsass%")
| table _time host user CommandLine
| head 200`
  )
  const [result, setResult] = useState<{ valid: boolean; reason: string } | null>(null)
  const [busy, setBusy] = useState(false)

  async function onValidate() {
    setBusy(true)
    try {
      const r = await validateSpl(query)
      setResult(r)
    } catch (e: any) {
      setResult({ valid: false, reason: e.message || String(e) })
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-5 max-w-3xl">
      <div>
        <h1 className="text-lg font-semibold">Hunt</h1>
        <p className="text-sm text-ink-400 mt-1">Validate investigation queries before use</p>
      </div>

      <div className="bg-surface-800 border border-surface-700 rounded-md p-4 space-y-3">
        <div className="text-sm font-medium">SPL</div>
        <textarea
          className="w-full text-xs bg-surface-900 border border-surface-700 rounded p-3 h-40 font-mono text-ink-200"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        <button
          onClick={onValidate}
          disabled={busy}
          className="text-sm px-3 py-1.5 bg-accent/90 hover:bg-accent rounded text-white disabled:opacity-50"
        >
          {busy ? "Checking…" : "Validate"}
        </button>
        {result && (
          <div className="flex items-center gap-2 text-xs">
            <span
              className={`px-2 py-0.5 rounded ${
                result.valid ? "bg-emerald-900/40 text-emerald-400" : "bg-red-900/40 text-sev-critical"
              }`}
            >
              {result.valid ? "Validated" : "Rejected"}
            </span>
            <span className="text-ink-400">{result.reason}</span>
          </div>
        )}
      </div>

      <div className="bg-surface-800 border border-surface-700 rounded-md p-4">
        <div className="text-sm font-medium mb-2">Policy</div>
        <ul className="text-sm text-ink-300 space-y-1.5 list-disc list-inside">
          <li>Every generated query is checked against forbidden operators before execution</li>
          <li>Destructive containment actions require human approval</li>
          <li>LLM output is never executed directly</li>
        </ul>
      </div>
    </div>
  )
}
