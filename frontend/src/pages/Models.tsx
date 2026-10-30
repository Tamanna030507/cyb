import { useEffect, useState } from "react"
import { getMetrics } from "../api/client"

export default function Models() {
  const [m, setM] = useState<Record<string, unknown> | null>(null)
  const [clear, setClear] = useState<any>(null)
  const [err, setErr] = useState("")

  useEffect(() => {
    getMetrics()
      .then(setM)
      .catch((e) => setErr(String(e.message || e)))
  }, [])

  useEffect(() => {
    fetch("/experiments/clear_eval_results.json")
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => d && setClear(d))
      .catch(() => null)
  }, [])

  const leakage = (m?.temporal_leakage_check as Record<string, unknown>) || {}
  const knownR = clear?.known_variants?.recall
  const unkR = clear?.unknown_variants?.recall

  return (
    <div className="space-y-6 max-w-3xl">
      <div>
        <h1 className="text-lg font-semibold">Models & evaluation</h1>
        <p className="text-sm text-ink-400 mt-1">
          Credibility signals: leakage must pass, unknown should be harder than known, poisoning must degrade recall
        </p>
      </div>

      {err && (
        <div className="bg-surface-800 border border-orange-800/50 rounded-md p-3 text-sm text-orange-300">
          Live API metrics unreachable — showing offline experiment files when available.
        </div>
      )}

      <div className="bg-surface-800 border border-surface-700 rounded-md p-4 flex items-center justify-between">
        <div>
          <div className="text-sm font-medium">Host-event ensemble</div>
          <div className="text-ink-300 text-sm mt-0.5 font-mono">xgb-ensemble-v1.0</div>
        </div>
        <div className="text-xs text-ink-400">
          Leakage:{" "}
          <span className={leakage.ok ? "text-emerald-400" : "text-red-400"}>
            {leakage.ok === true ? "passed" : leakage.ok === false ? "failed" : "run eval"}
          </span>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div className="bg-surface-800 border border-surface-700 rounded-md p-4 space-y-2 text-sm">
          <div className="font-medium">Offline metrics</div>
          <div className="flex justify-between"><span className="text-ink-400">PR-AUC</span><span className="font-mono">{String(m?.pr_auc ?? "—")}</span></div>
          <div className="flex justify-between"><span className="text-ink-400">Recall</span><span className="font-mono">{String(m?.recall ?? "—")}</span></div>
          <div className="flex justify-between"><span className="text-ink-400">Precision</span><span className="font-mono">{String(m?.precision ?? "—")}</span></div>
          <div className="flex justify-between"><span className="text-ink-400">Inference</span><span className="font-mono">{String(m?.inference_latency_ms ?? "—")} ms</span></div>
        </div>
        <div className="bg-surface-800 border border-surface-700 rounded-md p-4 space-y-2 text-sm">
          <div className="font-medium">Baselines</div>
          <div className="flex justify-between"><span className="text-ink-400">Rules-only</span><span className="font-mono">{String(m?.rules_only_recall ?? "—")}</span></div>
          <div className="flex justify-between"><span className="text-ink-400">Sigma-style</span><span className="font-mono">{String(m?.sigma_baseline_recall ?? "—")}</span></div>
        </div>
      </div>

      <div className="bg-surface-800 border border-surface-700 rounded-md p-4 space-y-3">
        <div className="text-sm font-medium">CLEAR-schema known vs unknown</div>
        {clear ? (
          <div className="space-y-3 text-sm">
            <div className="grid grid-cols-2 gap-4">
              <div className="bg-surface-900 border border-surface-700 rounded p-3">
                <div className="text-xs text-ink-400 mb-1">Known variants</div>
                <div className="font-mono text-lg">{typeof knownR === "number" ? knownR.toFixed(3) : knownR}</div>
                <div className="text-xs text-ink-400">recall</div>
              </div>
              <div className="bg-surface-900 border border-surface-700 rounded p-3">
                <div className="text-xs text-ink-400 mb-1">Unknown variants</div>
                <div className="font-mono text-lg">{typeof unkR === "number" ? unkR.toFixed(3) : unkR}</div>
                <div className="text-xs text-ink-400">recall — generalization gap</div>
              </div>
            </div>
            <div className="text-xs text-ink-400">
              Poisoning:{" "}
              {(clear.poisoning_on_clear_schema || [])
                .map((p: any) => `${p.poison_rate}→${Number(p.recall).toFixed(2)}`)
                .join(" · ")}
            </div>
            <div className="text-xs text-ink-400 border-t border-surface-700 pt-2">
              Schema-faithful mini sample (hard unknown variants). Full CLEAR corpus is on Kaggle — re-run loader on a real subset for production claims.
            </div>
          </div>
        ) : (
          <div className="text-sm text-ink-400">Run clear_eval to populate experiments/clear_eval_results.json</div>
        )}
      </div>
    </div>
  )
}
