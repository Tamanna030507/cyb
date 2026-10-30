import { Link } from "react-router-dom"

const rows = [
  { id: "A-4821", time: "14:22:08", host: "dc-prod-01", severity: "Critical", technique: "T1486", score: 94, status: "Open" },
  { id: "A-4819", time: "14:18:41", host: "srv-backup", severity: "High", technique: "T1003", score: 87, status: "Open" },
  { id: "A-4815", time: "14:11:03", host: "workstn-42", severity: "High", technique: "T1021", score: 81, status: "Open" },
  { id: "A-4802", time: "13:55:19", host: "fs-01", severity: "Medium", technique: "T1059", score: 68, status: "Triaged" },
  { id: "A-4798", time: "13:42:07", host: "dc-prod-01", severity: "Medium", technique: "T1070", score: 61, status: "Open" },
  { id: "A-4791", time: "13:20:44", host: "lap-88", severity: "Low", technique: "T1087", score: 42, status: "Closed" }
]

function sevClass(s: string) {
  if (s === "Critical") return "text-sev-critical"
  if (s === "High") return "text-sev-high"
  if (s === "Medium") return "text-sev-medium"
  return "text-sev-low"
}

export default function Alerts() {
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold">Alerts</h1>
          <p className="text-sm text-ink-400 mt-0.5">142 total · 38 open</p>
        </div>
        <div className="flex gap-2 text-xs">
          <select className="bg-surface-800 border border-surface-700 rounded px-2 py-1.5 text-ink-200">
            <option>Status: All</option>
            <option>Open</option>
            <option>Triaged</option>
            <option>Closed</option>
          </select>
          <select className="bg-surface-800 border border-surface-700 rounded px-2 py-1.5 text-ink-200">
            <option>Severity: All</option>
            <option>Critical</option>
            <option>High</option>
            <option>Medium</option>
            <option>Low</option>
          </select>
        </div>
      </div>

      <div className="bg-surface-800 border border-surface-700 rounded-md overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-xs text-ink-400 border-b border-surface-700">
              <th className="px-4 py-2.5 font-medium">ID</th>
              <th className="px-4 py-2.5 font-medium">Time</th>
              <th className="px-4 py-2.5 font-medium">Host</th>
              <th className="px-4 py-2.5 font-medium">Severity</th>
              <th className="px-4 py-2.5 font-medium">Technique</th>
              <th className="px-4 py-2.5 font-medium">Score</th>
              <th className="px-4 py-2.5 font-medium">Status</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id} className="border-b border-surface-700/60 hover:bg-surface-700/40">
                <td className="px-4 py-2.5">
                  <Link to={`/alerts/${r.id}`} className="text-accent hover:underline">
                    {r.id}
                  </Link>
                </td>
                <td className="px-4 py-2.5 text-ink-300">{r.time}</td>
                <td className="px-4 py-2.5">{r.host}</td>
                <td className={`px-4 py-2.5 font-medium ${sevClass(r.severity)}`}>{r.severity}</td>
                <td className="px-4 py-2.5 text-ink-300">{r.technique}</td>
                <td className="px-4 py-2.5">{r.score}</td>
                <td className="px-4 py-2.5 text-ink-300">{r.status}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}