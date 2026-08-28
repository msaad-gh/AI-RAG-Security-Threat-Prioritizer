"use client"

import { useEffect, useState } from "react"
import { incidentsApi } from "@/lib/api"

export default function IncidentDetail({ params }: { params: { id: string } }) {
  const [inc, setInc] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const [notes, setNotes] = useState("")
  const [status, setStatus] = useState("")

  useEffect(() => {
    incidentsApi.get(parseInt(params.id)).then(d => {
      setInc(d)
      setStatus(d.status)
      setNotes(d.human_review_notes || "")
      setLoading(false)
    })
  }, [params.id])

  async function save() {
    await incidentsApi.update(inc.id, {
      human_review_notes: notes,
      status: status,
      human_reviewed: true
    })
    alert("Review saved successfully!")
  }

  if (loading) {
    return (
      <div className="p-12 text-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto"></div>
      </div>
    )
  }

  if (!inc) {
    return <p className="p-6">Incident not found</p>
  }

  return (
    <div className="p-6 max-w-7xl mx-auto">
      <a href="/incidents" className="text-blue-600 mb-4 inline-block">← Back to Incidents</a>
      
      <div className="flex justify-between items-start mb-6">
        <div>
          <div className="flex gap-2 mb-2">
            <span className={`px-3 py-1 rounded-full text-sm font-medium risk-${inc.risk_level}`}>
              {inc.risk_level.toUpperCase()}
            </span>
            <span className="px-2 py-1 text-xs bg-gray-100 rounded">{inc.status}</span>
          </div>
          <h1 className="text-2xl font-bold">{inc.title}</h1>
        </div>
        <div className="text-right">
          <p className="text-3xl font-bold">{inc.overall_risk_score.toFixed(0)}</p>
          <p className="text-sm text-gray-600">Risk Score</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-6">
          <div className="bg-white rounded-lg shadow p-6">
            <h3 className="text-lg font-semibold mb-4">AI Analysis</h3>
            {inc.llm_summary && (
              <p className="font-medium mb-4">{inc.llm_summary}</p>
            )}
            {inc.llm_explanation && (
              <div className="prose text-gray-600 whitespace-pre-line">
                {inc.llm_explanation}
              </div>
            )}
            {inc.llm_recommendations && (
              <div className="mt-4">
                <h4 className="font-semibold mb-2">Recommendations:</h4>
                <ul className="list-disc list-inside space-y-1">
                  {inc.llm_recommendations.map((r: string, i: number) => (
                    <li key={i}>{r}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>

          <div className="bg-white rounded-lg shadow p-6">
            <h3 className="text-lg font-semibold mb-4">7-Factor Risk Breakdown</h3>
            {Object.entries(inc.risk_factors).map(([k, v]) => (
              <div key={k} className="mb-3">
                <div className="flex justify-between mb-1">
                  <span className="text-sm font-medium text-gray-700">
                    {k.replace(/_/g, " ").replace("score", "")}
                  </span>
                  <span className="text-sm text-gray-600">
                    {(v as number).toFixed(1)}/10
                  </span>
                </div>
                <div className="w-full bg-gray-200 rounded-full h-2">
                  <div
                    className={`h-2 rounded-full ${
                      (v as number) >= 8 ? "bg-red-600" :
                      (v as number) >= 6 ? "bg-orange-600" : "bg-green-600"
                    }`}
                    style={{ width: `${(v as number) * 10}%` }}
                  ></div>
                </div>
              </div>
            ))}
          </div>

          {inc.mitre_tactics && (
            <div className="bg-white rounded-lg shadow p-6">
              <h3 className="text-lg font-semibold mb-4">MITRE ATT&CK</h3>
              <div className="flex flex-wrap gap-2">
                {inc.mitre_tactics.map((t: string, i: number) => (
                  <span key={i} className="px-3 py-1 bg-blue-100 text-blue-800 rounded-full text-sm">
                    {t}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>

        <div className="space-y-6">
          <div className="bg-white rounded-lg shadow p-6">
            <h3 className="text-lg font-semibold mb-4">Analyst Review</h3>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-1">Status</label>
                <select
                  value={status}
                  onChange={e => setStatus(e.target.value)}
                  className="w-full border rounded px-3 py-2"
                >
                  <option value="new">New</option>
                  <option value="triaging">Triaging</option>
                  <option value="investigating">Investigating</option>
                  <option value="contained">Contained</option>
                  <option value="resolved">Resolved</option>
                  <option value="false_positive">False Positive</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Notes</label>
                <textarea
                  value={notes}
                  onChange={e => setNotes(e.target.value)}
                  rows={4}
                  className="w-full border rounded px-3 py-2"
                  placeholder="Analysis notes..."
                />
              </div>
              <button
                onClick={save}
                className="w-full bg-blue-600 text-white py-2 rounded hover:bg-blue-700 font-medium"
              >
                Save Review
              </button>
              {inc.human_reviewed && (
                <p className="text-xs text-green-600">✓ Reviewed by analyst</p>
              )}
            </div>
          </div>

          <div className="bg-white rounded-lg shadow p-6">
            <h3 className="text-lg font-semibold mb-4">Details</h3>
            <div className="space-y-2 text-sm">
              <div>
                <span className="text-gray-600">Events:</span>
                <span className="ml-2 font-medium">{inc.event_count}</span>
              </div>
              <div>
                <span className="text-gray-600">Detected:</span>
                <span className="ml-2">{new Date(inc.detected_at).toLocaleString()}</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}