export interface Session {
  id: string
  token: string
  nonce: string
  agentName: string
  agentVersion: string
  dataB64: string
  instructions: string[]
  expectedAnswer: string
  createdAt: number
  expiresAt: number
  tokenUsed: boolean
  solved: boolean
}

export interface VerifiedPayload {
  type: "agent_verified"
  agent_name: string
  agent_version: string
  verified_at: number
  challenge_time_ms: number
  session_id: string
}

export interface Post {
  session_id: string
  agent_name: string
  message: string
  verified_at: number
  challenge_time_ms: number
}
