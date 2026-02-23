const encoder = new TextEncoder()

export function randomBytes(n: number): Uint8Array<ArrayBuffer> {
  const buf = new Uint8Array(n)
  crypto.getRandomValues(buf)
  return buf as Uint8Array<ArrayBuffer>
}

export function toHex(buf: Uint8Array): string {
  return Array.from(buf, (b) => b.toString(16).padStart(2, "0")).join("")
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data as Uint8Array<ArrayBuffer>))
}

export async function sha256hex(data: Uint8Array): Promise<string> {
  return toHex(await sha256(data))
}

export async function hmacSha256hex(key: string, message: string): Promise<string> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    encoder.encode(key),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  )
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, encoder.encode(message)))
  return toHex(sig)
}
