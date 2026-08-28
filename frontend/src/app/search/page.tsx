"use client"

import { useState } from "react"
import { ragApi } from "@/lib/api"
import { Search, BookOpen } from "lucide-react"

export default function SearchPage() {
  const [q, setQuery] = useState("")
  const [results, setResults] = useState<any[]>([])
  const [loading, setLoading] = useState(false)
  const [searched, setSearched] = useState(false)

  async function search() {
    if (!q.trim()) return
    try {
      setLoading(true)
      const d = await ragApi.query(q, 10)
      setResults(d.results)
      setSearched(true)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="p-6 max-w-4xl mx-auto">
      <h2 className="text-2xl font-bold mb-6">Threat Intelligence Search</h2>
      
      <div className="bg-white rounded-lg shadow mb-6 p-6">
        <div className="flex gap-2">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
            <input
              type="text"
              value={q}
              onChange={e => setQuery(e.target.value)}
              onKeyDown={e => e.key === "Enter" && search()}
              placeholder="Search MITRE, CVEs..."
              className="w-full pl-10 pr-4 py-3 border rounded-lg"
            />
          </div>
          <button
            onClick={search}
            disabled={loading || !q.trim()}
            className="px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
          >
            {loading ? "Searching..." : "Search"}
          </button>
        </div>
        
        <div className="mt-4">
          <p className="text-sm text-gray-600 mb-2">Try:</p>
          <div className="flex flex-wrap gap-2">
            {["T1059", "SQL injection", "CVE-2024-21762", "lateral movement"].map(x => (
              <button
                key={x}
                onClick={() => setQuery(x)}
                className="px-3 py-1 bg-gray-100 rounded text-sm hover:bg-gray-200"
              >
                {x}
              </button>
            ))}
          </div>
        </div>
      </div>

      {searched && (
        <div className="bg-white rounded-lg shadow">
          <div className="px-6 py-4 border-b">
            <h3 className="font-semibold">
              {results.length > 0 ? `Found ${results.length} results` : "No results"}
            </h3>
          </div>
          <div className="divide-y">
            {results.map((r, i) => (
              <div key={i} className="p-6 hover:bg-gray-50">
                <div className="flex items-center gap-2 mb-2">
                  <BookOpen className="w-4 h-4 text-blue-600" />
                  <span className="text-xs font-medium text-gray-500 uppercase">
                    {r.content_type}
                  </span>
                  {r.mitre_id && (
                    <span className="px-2 py-0.5 bg-purple-100 text-purple-800 rounded text-xs">
                      {r.mitre_id}
                    </span>
                  )}
                </div>
                <h4 className="text-lg font-semibold mb-2">{r.title}</h4>
                <p className="text-gray-600 mb-2">{r.content}</p>
                <p className="text-xs text-gray-500">
                  Relevance: {(r.relevance_score * 10).toFixed(1)}%
                </p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}