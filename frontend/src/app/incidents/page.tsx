"use client"

import { useEffect, useState } from "react"
import { incidentsApi } from "@/lib/api"

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState("all")

  useEffect(() => {
    incidentsApi.list(1, 50, filter).then(d => {
      setIncidents(d.incidents)
      setLoading(false)
    })
  }, [filter])

  return (
    <div className="p-6 max-w-7xl mx-auto">
      <h2 className="text-2xl font-bold mb-6">Security Incidents</h2>
      
      <div className="mb-4">
        <select value={filter} onChange={e => setFilter(e.target.value)} className="border rounded px-3 py-2">
          <option value="all">All Risk Levels</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
      </div>

      <div className="bg-white rounded-lg shadow overflow-x-auto">
        {loading ? (
          <p className="p-12 text-center">Loading incidents...</p>
        ) : (
          <table className="min-w-full">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Risk</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Title</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Score</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Events</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Detected</th>
              </tr>
            </thead>
            <tbody className="divide-y">
              {incidents.map(i => (
                <tr key={i.id} className="hover:bg-gray-50">
                  <td className="px-6 py-4">
                    <span className={`px-3 py-1 rounded-full text-xs font-medium risk-${i.risk_level}`}>
                      {i.risk_level.toUpperCase()}
                    </span>
                  </td>
                  <td className="px-6 py-4">
                    <a href={`/incidents/${i.id}`} className="text-blue-600 hover:text-blue-800 font-medium">
                      {i.title}
                    </a>
                    {i.mitre_tactics && (
                      <p className="text-xs text-gray-500 mt-1">
                        {i.mitre_tactics.slice(0, 2).join(", ")}
                      </p>
                    )}
                  </td>
                  <td className="px-6 py-4">
                    <div className="flex items-center">
                      <div className="w-20 bg-gray-200 rounded-full h-2 mr-2">
                        <div
                          className={`h-2 rounded-full ${
                            i.risk_level === "critical" ? "bg-red-600" :
                            i.risk_level === "high" ? "bg-orange-600" : "bg-yellow-600"
                          }`}
                          style={{ width: `${i.overall_risk_score}%` }}
                        ></div>
                      </div>
                      <span className="text-sm">{i.overall_risk_score.toFixed(0)}</span>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <span className="px-2 py-1 text-xs bg-gray-100 rounded">{i.status}</span>
                  </td>
                  <td className="px-6 py-4">{i.event_count}</td>
                  <td className="px-6 py-4">{new Date(i.detected_at).toLocaleDateString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <p className="mt-4 text-sm text-gray-600">
        Showing {incidents.length} incidents
      </p>
    </div>
  )
}