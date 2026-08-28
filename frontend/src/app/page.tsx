"use client"

import { useEffect, useState } from "react"
import { dashboardApi, incidentsApi } from "@/lib/api"
import { Shield, AlertTriangle, CheckCircle, TrendingUp } from "lucide-react"

export default function Dashboard() {
  const [stats, setStats] = useState<any>(null)
  const [incidents, setIncidents] = useState<any[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    Promise.all([
      dashboardApi.getStats(),
      incidentsApi.list(1, 10)
    ]).then(([s, i]) => {
      setStats(s)
      setIncidents(i.incidents)
      setLoading(false)
    })
  }, [])

  if (loading) {
    return (
      <div className="p-12 text-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
        <p className="text-gray-600">Loading ThreatIQ...</p>
      </div>
    )
  }

  return (
    <div className="p-6 max-w-7xl mx-auto">
      <h2 className="text-2xl font-bold mb-6">Security Dashboard</h2>
      
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
        <StatCard title="Total Incidents" value={stats?.total_incidents || 0} icon={Shield} color="blue" />
        <StatCard title="Critical/High" value={(stats?.critical_incidents || 0) + (stats?.high_incidents || 0)} icon={AlertTriangle} color="red" />
        <StatCard title="Resolved (24h)" value={stats?.resolved_incidents_24h || 0} icon={CheckCircle} color="green" />
        <StatCard title="New (24h)" value={stats?.new_incidents_24h || 0} icon={TrendingUp} color="purple" />
      </div>

      <div className="bg-white rounded-lg shadow">
        <div className="px-6 py-4 border-b">
          <h3 className="font-semibold">Recent Incidents</h3>
        </div>
        <table className="min-w-full">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Risk</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Title</th>
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
      </div>
    </div>
  )
}

function StatCard({ title, value, icon: Icon, color }: { title: string; value: number; icon: any; color: string }) {
  const colors: any = {
    blue: "text-blue-600",
    red: "text-red-600",
    green: "text-green-600",
    purple: "text-purple-600"
  }
  
  return (
    <div className="bg-white rounded-lg shadow p-6">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-gray-600">{title}</p>
          <p className="text-3xl font-bold mt-1">{value}</p>
        </div>
        <Icon className={`w-10 h-10 ${colors[color]}`} />
      </div>
    </div>
  )
}