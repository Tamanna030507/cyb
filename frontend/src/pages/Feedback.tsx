import { useState } from "react"
import { submitFeedback } from "../api/client"

export default function Feedback() {
  const [alertId, setAlertId] = useState("A-4821")
  const [label, setLabel] = useState<"true_positive" | "false_positive">("false_positive")
  const [analyst, setAnalyst] = useState("")
  const [reason, setReason] = useState("")
  const [msg, setMsg] = useState("")
  const [busy, setBusy] = useState(false)

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true)
    setMsg("")
    try {
      const r = await submitFeedback({ alert_id: alertId, label, analyst, reason })
      setMsg(`Accepted · feedback_id ${r.feedback_id}`)
    } catch (err: any) {
      setMsg(`Error: ${err.message || err}`)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-5 max-w-2xl">
      <div>
        <h1 className="text-lg font-semibold">Analyst feedback</h1>
        <p className="text-sm text-ink-400 mt-1">Labels with provenance flow back into training</p>
      </div>

      <form onSubmit={onSubmit} className="bg-surface-800 border border-surface-700 rounded-md p-4 space-y-4">
        <div>
          <label className="text-xs text-ink-400 block mb-1">Alert ID</label>
          <input
            className="w-full bg-surface-900 border border-surface-700 rounded px-3 py-2 text-sm"
            value={alertId}
            onChange={(e) => setAlertId(e.target.value)}
          />
        </div>
        <div>
          <label className="text-xs text-ink-400 block mb-1">Label</label>
          <select
            className="w-full bg-surface-900 border border-surface-700 rounded px-3 py-2 text-sm"
            value={label}
            onChange={(e) => setLabel(e.target.value as any)}
          >
            <option value="true_positive">True positive</option>
            <option value="false_positive">False positive</option>
          </select>
        </div>
        <div>
          <label className="text-xs text-ink-400 block mb-1">Analyst</label>
          <input
            className="w-full bg-surface-900 border border-surface-700 rounded px-3 py-2 text-sm"
            value={analyst}
            onChange={(e) => setAnalyst(e.target.value)}
            placeholder="your.name"
            required
          />
        </div>
        <div>
          <label className="text-xs text-ink-400 block mb-1">Reason</label>
          <textarea
            className="w-full bg-surface-900 border border-surface-700 rounded px-3 py-2 text-sm h-24"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="Known backup process, false positive"
          />
        </div>
        <button
          type="submit"
          disabled={busy}
          className="text-sm px-4 py-2 bg-accent/90 hover:bg-accent rounded text-white disabled:opacity-50"
        >
          {busy ? "Submitting…" : "Submit feedback"}
        </button>
        {msg && <div className="text-sm text-ink-300">{msg}</div>}
      </form>

      <div className="text-xs text-ink-400">
        Feedback is stored with analyst identity, timestamp, and reason.
        Retraining only uses provenance-tracked labels.
      </div>
    </div>
  )
}
