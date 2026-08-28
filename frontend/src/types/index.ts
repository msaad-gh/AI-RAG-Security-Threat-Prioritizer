export type RiskLevel = "critical" | "high" | "medium" | "low" | "info"
export type IncidentStatus = "new" | "triaging" | "investigating" | "contained" | "resolved" | "false_positive"

export interface RiskScoreFactors {
  threat_severity_score: number
  asset_criticality_score: number
  attack_sophistication_score: number
  confidence_score: number
  exposure_score: number
  temporal_score: number
  mitigation_score: number
}

export interface Incident {
  id: number
  incident_id: string
  title: string
  description?: string
  status: IncidentStatus
  risk_factors: RiskScoreFactors
  overall_risk_score: number
  risk_level: RiskLevel
  mitre_tactics?: string[]
  mitre_techniques?: string[]
  llm_explanation?: string
  llm_summary?: string
  llm_recommendations?: string[]
  human_reviewed: boolean
  human_review_notes?: string
  detected_at: string
  created_at: string
  event_count: number
}

export interface IncidentListItem {
  id: number
  incident_id: string
  title: string
  risk_level: RiskLevel
  overall_risk_score: number
  status: IncidentStatus
  event_count: number
  detected_at: string
  mitre_tactics?: string[]
}

export interface IncidentListResponse {
  incidents: IncidentListItem[]
  total: number
  page: number
  page_size: number
}

export interface DashboardStats {
  total_incidents: number
  critical_incidents: number
  high_incidents: number
  medium_incidents: number
  low_incidents: number
  new_incidents_24h: number
}

export interface RAGResult {
  id: number
  title: string
  content: string
  content_type: string
  mitre_id?: string
  cve_id?: string
  relevance_score: number
}

export interface RAGQueryResponse {
  query: string
  results: RAGResult[]
  total_results: number
}