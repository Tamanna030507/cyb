const API_KEY = import.meta.env.VITE_API_KEY || "dev-key-change-me"
const BASE = import.meta.env.VITE_API_BASE || "/api"

async function req<T>(path: string, opts: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "X-Api-Key": API_KEY,
    ...(opts.headers as Record<string, string> || {})
  }
  const res = await fetch(`${BASE}${path}`, { ...opts, headers })
  if (!res.ok) {
    throw new Error(`API ${res.status}: ${await res.text()}`)
  }
  return res.json()
}

export function getHealth() {
  return req<{ status: string; model_ready: boolean }>("/health")
}

export function getMetrics() {
  return req<Record<string, unknown>>("/metrics/summary")
}

export function scoreEvents(body: {
  host_id: string
  user_id?: string
  events: Array<Record<string, unknown>>
}) {
  return req<{
    host_id: string
    score: number
    severity: string
    alert_id: string
    explanation: string
    feature_contributions: Array<{
      feature: string
      value: number
      contribution: number
      mitre: string[]
    }>
    latency_ms: number
  }>("/score", { method: "POST", body: JSON.stringify(body) })
}

export function submitFeedback(body: {
  alert_id: string
  label: "true_positive" | "false_positive"
  analyst: string
  reason: string
}) {
  return req<{ status: string; feedback_id: string }>("/feedback", {
    method: "POST",
    body: JSON.stringify(body)
  })
}

export function validateSpl(query: string) {
  return req<{ valid: boolean; reason: string }>("/validate-spl", {
    method: "POST",
    body: JSON.stringify({ query })
  })
}