import type { Session } from "./types"

export interface SessionStore {
  get(id: string): Promise<Session | null>
  set(id: string, session: Session): Promise<void>
  delete(id: string): Promise<void>
}

export class MemoryStore implements SessionStore {
  private map = new Map<string, Session>()

  async get(id: string) {
    const s = this.map.get(`session:${id}`) ?? null
    if (s && Date.now() > s.expiresAt) {
      this.map.delete(`session:${id}`)
      return null
    }
    return s
  }

  async set(id: string, session: Session) {
    this.map.set(`session:${id}`, session)
  }

  async delete(id: string) {
    this.map.delete(`session:${id}`)
  }
}

export class KVSessionStore implements SessionStore {
  constructor(private kv: KVNamespace) {}

  async get(id: string) {
    const val = await this.kv.get(`session:${id}`, "json") as Session | null
    if (val && Date.now() > val.expiresAt) {
      await this.kv.delete(`session:${id}`)
      return null
    }
    return val
  }

  async set(id: string, session: Session) {
    const ttlSeconds = Math.ceil((session.expiresAt - Date.now()) / 1000) + 5
    await this.kv.put(`session:${id}`, JSON.stringify(session), { expirationTtl: Math.max(ttlSeconds, 60) })
  }

  async delete(id: string) {
    await this.kv.delete(`session:${id}`)
  }
}
