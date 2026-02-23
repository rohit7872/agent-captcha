import { randomBytes, sha256, sha256hex, toHex } from "./crypto"

// --- Utility helpers ---

function randInt(min: number, max: number): number {
  return min + Math.floor(Math.random() * (max - min))
}

function pick<T>(arr: T[]): T {
  return arr[randInt(0, arr.length)]
}

function shuffle<T>(arr: T[]): T[] {
  const a = [...arr]
  for (let i = a.length - 1; i > 0; i--) {
    const j = randInt(0, i + 1)
    ;[a[i], a[j]] = [a[j], a[i]]
  }
  return a
}

const SMALL_WORDS: Record<number, string> = {
  0: "zero", 1: "one", 2: "two", 3: "three", 4: "four", 5: "five",
  6: "six", 7: "seven", 8: "eight", 9: "nine", 10: "ten", 11: "eleven",
  12: "twelve", 13: "thirteen", 14: "fourteen", 15: "fifteen", 16: "sixteen",
  17: "seventeen", 18: "eighteen", 19: "nineteen", 20: "twenty",
}

function fmtNum(n: number): string {
  const r = Math.random()
  if (r < 0.35) return `0x${n.toString(16).toUpperCase()}`
  if (r < 0.55 && n <= 20 && SMALL_WORDS[n]) return SMALL_WORDS[n]
  return `${n}`
}

function fmtDec(n: number): string {
  return `${n}` // always decimal for offsets to stay unambiguous
}

function ordinal(n: number): string {
  if (n === 2) return "2nd"
  if (n === 3) return "3rd"
  return `${n}th`
}

// --- Synonym pools ---

const SLICE_VERBS = ["Take", "Extract", "Select", "Grab", "Read", "Pull out", "Isolate"]
const BYTE_WORDS = ["bytes", "octets"]
const REVERSE_PHRASES = [
  "reverse their order",
  "flip the sequence end-to-end",
  "mirror the byte order",
  "reverse the byte sequence",
  "arrange them in reverse order",
]
const XOR_PHRASES = (key: string) => [
  `XOR each byte with ${key}`,
  `exclusive-or every byte with the value ${key}`,
  `apply XOR ${key} to each byte`,
  `bitwise XOR each with ${key}`,
]
const CONCAT_FINAL = [
  (n: number) => `Concatenate the raw byte results from all ${n} steps in order, and return the SHA-256 hex digest of the concatenated bytes.`,
  (n: number) => `Join the byte outputs of every step (1 through ${n}) sequentially, then SHA-256 hash the combined bytes and return the hex digest.`,
  (n: number) => `Chain together the raw outputs of each of the ${n} preceding steps and produce the SHA-256 hex digest of that concatenation.`,
  (n: number) => `Merge the ${n} byte arrays from the previous steps into one (step 1 first, step ${n} last), then output the SHA-256 hex string.`,
]

function rangePhrase(start: number, end: number): string {
  const s = fmtDec(start), e = fmtDec(end)
  return pick([
    `from offset ${s} to offset ${e}`,
    `starting at index ${s}, ending before index ${e}`,
    `in the range [${s}, ${e})`,
    `between positions ${s} and ${e} (exclusive end)`,
    `from byte ${s} up to (but not including) byte ${e}`,
  ])
}

function inclusiveRangePhrase(start: number, end: number): string {
  const s = fmtDec(start), e = fmtDec(end)
  return pick([
    `from offset ${s} through offset ${e}`,
    `starting at index ${s} up to and including index ${e}`,
    `covering bytes ${s} to ${e} inclusive`,
    `in the range [${s}, ${e}]`,
  ])
}

// --- Transform definitions ---

interface TransformDef {
  generate(dataLen: number): { params: Record<string, number | number[]>; instruction: string }
  execute(data: Uint8Array, params: Record<string, number | number[]>): Uint8Array | Promise<Uint8Array>
}

const transforms: TransformDef[] = [
  // 0: Reverse + XOR
  {
    generate(dataLen) {
      const start = randInt(0, dataLen - 16)
      const end = randInt(start + 16, Math.min(start + 64, dataLen))
      const xorKey = randInt(1, 256)
      const v = pick(SLICE_VERBS), bw = pick(BYTE_WORDS)
      const rng = rangePhrase(start, end)
      const rev = pick(REVERSE_PHRASES), xp = pick(XOR_PHRASES(fmtNum(xorKey)))
      const instruction = pick([
        `${v} ${bw} ${rng}, ${rev}, then ${xp}.`,
        `First, isolate data[${fmtDec(start)}:${fmtDec(end)}]. Next, ${rev}. Then ${xp}.`,
        `result = data[${fmtDec(start)}:${fmtDec(end)}].reverse().map(b => b ^ ${fmtNum(xorKey)})`,
        `${v} ${fmtDec(end)} - ${fmtDec(start)} = ${end - start} consecutive ${bw} beginning at byte ${fmtDec(start)}. ${rev[0].toUpperCase() + rev.slice(1)} and ${xp}.`,
        `Starting at position ${fmtDec(start)}, grab the next ${end - start} ${bw}. ${rev[0].toUpperCase() + rev.slice(1)}, then ${xp}.`,
      ])
      return { params: { start, end, xorKey }, instruction }
    },
    execute(data, { start, end, xorKey }) {
      const s = start as number, e = end as number, k = xorKey as number
      const slice = data.slice(s, e).reverse()
      return Uint8Array.from(slice, (b) => b ^ k)
    },
  },

  // 1: Hash slice
  {
    generate(dataLen) {
      const start = randInt(0, dataLen - 16)
      const end = randInt(start + 16, Math.min(start + 64, dataLen))
      const n = randInt(4, 17)
      const rng = inclusiveRangePhrase(start, end)
      const instruction = pick([
        `${pick(SLICE_VERBS)} ${pick(BYTE_WORDS)} ${rng}, compute the SHA-256 hash, and return only the first ${fmtNum(n)} bytes of the digest.`,
        `SHA-256(data[${fmtDec(start)}..=${fmtDec(end)}])[0:${fmtNum(n)}]`,
        `Hash the ${pick(BYTE_WORDS)} ${rng} with SHA-256. Truncate the result to its first ${fmtNum(n)} bytes.`,
        `Compute SHA-256 over the slice ${rng} (inclusive). Return the leading ${fmtNum(n)} ${pick(BYTE_WORDS)} of the hash output.`,
        `Take data[${fmtDec(start)}] through data[${fmtDec(end)}] inclusive, SHA-256 them, keep only the first ${fmtNum(n)} bytes.`,
      ])
      return { params: { start, end, n }, instruction }
    },
    async execute(data, { start, end, n }) {
      const s = start as number, e = end as number, nb = n as number
      const hash = await sha256(data.slice(s, e + 1))
      return hash.slice(0, nb)
    },
  },

  // 2: Nth byte extraction
  {
    generate(dataLen) {
      const start = randInt(0, dataLen - 32)
      const end = randInt(start + 32, Math.min(start + 80, dataLen))
      const nth = randInt(2, 6)
      const instruction = pick([
        `Starting from offset ${fmtDec(start)}, take every ${ordinal(nth)} byte up to (but not including) offset ${fmtDec(end)}, and concatenate them.`,
        `Collect data[${fmtDec(start)}], data[${fmtDec(start)} + ${nth}], data[${fmtDec(start)} + ${2 * nth}], ... while the index stays below ${fmtDec(end)}.`,
        `${pick(SLICE_VERBS)} every ${ordinal(nth)} ${pick(BYTE_WORDS).slice(0, -1)} in the range [${fmtDec(start)}, ${fmtDec(end)}), i.e. indices ${fmtDec(start)}, ${start + nth}, ${start + 2 * nth}, and so on.`,
        `From position ${fmtDec(start)}, sample one byte then skip ${nth - 1}, repeating until you reach position ${fmtDec(end)}. Return the sampled bytes.`,
        `Stride through data with step size ${fmtNum(nth)}, starting at index ${fmtDec(start)} and stopping before index ${fmtDec(end)}.`,
      ])
      return { params: { start, end, nth }, instruction }
    },
    execute(data, { start, end, nth }) {
      const s = start as number, e = end as number, n = nth as number
      const result: number[] = []
      for (let i = s; i < e; i += n) result.push(data[i])
      return new Uint8Array(result)
    },
  },

  // 3: Sum modulo
  {
    generate(dataLen) {
      const start = randInt(0, dataLen - 16)
      const end = randInt(start + 16, Math.min(start + 64, dataLen))
      const mod = randInt(2, 257)
      const rng = rangePhrase(start, end)
      const instruction = pick([
        `${pick(SLICE_VERBS)} ${pick(BYTE_WORDS)} ${rng}. Sum all byte values, compute the remainder when divided by ${fmtNum(mod)}. Return this single value as a one-byte result.`,
        `Add up every byte in data[${fmtDec(start)}:${fmtDec(end)}], then take the result modulo ${fmtNum(mod)}. Output that single byte.`,
        `Let S = sum of data[${fmtDec(start)}] + data[${fmtDec(start) + 1}] + ... + data[${fmtDec(end)} - 1]. Return a single byte equal to S % ${fmtNum(mod)}.`,
        `Compute (data[${fmtDec(start)}] + data[${start + 1}] + ... + data[${end - 1}]) mod ${fmtNum(mod)} and return it as one byte.`,
        `Sum all ${pick(BYTE_WORDS)} ${rng}, reduce modulo ${fmtNum(mod)}, and return the single-byte remainder.`,
      ])
      return { params: { start, end, mod }, instruction }
    },
    execute(data, { start, end, mod }) {
      const s = start as number, e = end as number, m = mod as number
      let sum = 0
      for (let i = s; i < e; i++) sum += data[i]
      return new Uint8Array([sum % m])
    },
  },

  // 4: Bitwise NOT
  {
    generate(dataLen) {
      const start = randInt(0, dataLen - 16)
      const end = randInt(start + 16, Math.min(start + 64, dataLen))
      const rng = rangePhrase(start, end)
      const instruction = pick([
        `${pick(SLICE_VERBS)} ${pick(BYTE_WORDS)} ${rng} and flip all bits in each byte (bitwise NOT, masked to 8 bits).`,
        `For each byte in data[${fmtDec(start)}:${fmtDec(end)}], compute ~byte & 0xFF.`,
        `Invert every bit of the ${pick(BYTE_WORDS)} ${rng}. Each output byte = 255 minus the input byte.`,
        `Apply one's complement to each byte ${rng}. That is, XOR each with ${fmtNum(255)}.`,
        `Take the bitwise complement of every byte ${rng} (keep only the low 8 bits).`,
      ])
      return { params: { start, end }, instruction }
    },
    execute(data, { start, end }) {
      const s = start as number, e = end as number
      return Uint8Array.from(data.slice(s, e), (b) => (~b) & 0xff)
    },
  },

  // 5: Conditional byte — if byte >= threshold: XOR with A, else XOR with B
  {
    generate(dataLen) {
      const start = randInt(0, dataLen - 16)
      const end = randInt(start + 16, Math.min(start + 48, dataLen))
      const threshold = randInt(64, 192)
      const xorA = randInt(1, 256)
      const xorB = randInt(1, 256)
      const rng = rangePhrase(start, end)
      const instruction = pick([
        `For each byte ${rng}: if the byte is >= ${fmtNum(threshold)}, XOR it with ${fmtNum(xorA)}; otherwise XOR it with ${fmtNum(xorB)}.`,
        `${pick(SLICE_VERBS)} ${pick(BYTE_WORDS)} ${rng}. Apply a conditional XOR: bytes at or above ${fmtNum(threshold)} get XOR'd with ${fmtNum(xorA)}, bytes below ${fmtNum(threshold)} get XOR'd with ${fmtNum(xorB)}.`,
        `Process data[${fmtDec(start)}:${fmtDec(end)}] byte by byte. result[i] = (byte >= ${fmtNum(threshold)}) ? byte ^ ${fmtNum(xorA)} : byte ^ ${fmtNum(xorB)}.`,
        `Map each byte b in the range ${rng} to: b ^ ${fmtNum(xorA)} when b >= ${fmtNum(threshold)}, or b ^ ${fmtNum(xorB)} when b < ${fmtNum(threshold)}.`,
        `Conditionally XOR the ${pick(BYTE_WORDS)} ${rng}. The threshold is ${fmtNum(threshold)} — bytes meeting or exceeding it use key ${fmtNum(xorA)}, the rest use key ${fmtNum(xorB)}.`,
      ])
      return { params: { start, end, threshold, xorA, xorB }, instruction }
    },
    execute(data, { start, end, threshold, xorA, xorB }) {
      const s = start as number, e = end as number
      const t = threshold as number, a = xorA as number, b = xorB as number
      return Uint8Array.from(data.slice(s, e), (byte) =>
        byte >= t ? byte ^ a : byte ^ b
      )
    },
  },

  // 6: Hash chain — SHA-256 iterated N times, truncate to M bytes
  {
    generate(dataLen) {
      const start = randInt(0, dataLen - 16)
      const end = randInt(start + 16, Math.min(start + 48, dataLen))
      const rounds = randInt(2, 8)
      const truncate = randInt(4, 17)
      const rng = inclusiveRangePhrase(start, end)
      const instruction = pick([
        `${pick(SLICE_VERBS)} ${pick(BYTE_WORDS)} ${rng}. Compute SHA-256, then hash the result again, repeating for a total of ${fmtNum(rounds)} rounds. Return the first ${fmtNum(truncate)} bytes.`,
        `Let h = data[${fmtDec(start)}..=${fmtDec(end)}]. Repeat ${fmtNum(rounds)} times: h = SHA-256(h). Return h[0:${fmtNum(truncate)}].`,
        `Take the slice ${rng} (inclusive) and iteratively SHA-256 it ${fmtNum(rounds)} times. Truncate the final hash to ${fmtNum(truncate)} ${pick(BYTE_WORDS)}.`,
        `Hash-chain: start with ${pick(BYTE_WORDS)} ${rng}, apply SHA-256 ${fmtNum(rounds)} consecutive times, then keep only the leading ${fmtNum(truncate)} bytes of the last hash.`,
        `Compute SHA-256 of data[${fmtDec(start)}] through data[${fmtDec(end)}] inclusive. Feed that hash back into SHA-256, ${rounds - 1} more time${rounds - 1 === 1 ? '' : 's'} (${fmtNum(rounds)} total). Output the first ${fmtNum(truncate)} bytes.`,
      ])
      return { params: { start, end, rounds, truncate }, instruction }
    },
    async execute(data, { start, end, rounds, truncate }) {
      const s = start as number, e = end as number
      const r = rounds as number, t = truncate as number
      let h: Uint8Array = data.slice(s, e + 1)
      for (let i = 0; i < r; i++) h = await sha256(h)
      return h.slice(0, t)
    },
  },

  // 7: Byte affine — (byte * A + B) % 256
  {
    generate(dataLen) {
      const start = randInt(0, dataLen - 16)
      const end = randInt(start + 16, Math.min(start + 48, dataLen))
      // Use odd multiplier to keep it invertible mod 256
      const mul = randInt(1, 128) * 2 + 1
      const add = randInt(0, 256)
      const rng = rangePhrase(start, end)
      const instruction = pick([
        `For each byte ${rng}, compute (byte * ${fmtNum(mul)} + ${fmtNum(add)}) mod 256.`,
        `Apply an affine transform to ${pick(BYTE_WORDS)} ${rng}: multiply by ${fmtNum(mul)}, add ${fmtNum(add)}, take mod 256.`,
        `${pick(SLICE_VERBS)} ${pick(BYTE_WORDS)} ${rng}. Transform each: out = (b * ${fmtNum(mul)} + ${fmtNum(add)}) % 256.`,
        `Map every byte b in data[${fmtDec(start)}:${fmtDec(end)}] to (${fmtNum(mul)} * b + ${fmtNum(add)}) & 0xFF.`,
        `Affine cipher on ${pick(BYTE_WORDS)} ${rng}: result[i] = (${fmtNum(mul)} * input[i] + ${fmtNum(add)}) modulo ${fmtNum(256)}.`,
      ])
      return { params: { start, end, mul, add }, instruction }
    },
    execute(data, { start, end, mul, add }) {
      const s = start as number, e = end as number
      const m = mul as number, a = add as number
      return Uint8Array.from(data.slice(s, e), (b) => (b * m + a) & 0xff)
    },
  },

  // 8: Nibble substitution — apply random 16-entry lookup table to each nibble
  {
    generate(dataLen) {
      const start = randInt(0, dataLen - 8)
      const end = randInt(start + 8, Math.min(start + 32, dataLen))
      const table = shuffle([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
      const tableStr = table.map(v => v.toString(16).toUpperCase()).join(", ")
      const rng = rangePhrase(start, end)
      const instruction = pick([
        `${pick(SLICE_VERBS)} ${pick(BYTE_WORDS)} ${rng}. For each byte, substitute both nibbles using the table S = [${tableStr}]. High nibble: S[byte >> 4], low nibble: S[byte & 0xF]. Recombine as (S[high] << 4) | S[low].`,
        `Apply nibble substitution to data[${fmtDec(start)}:${fmtDec(end)}] using S-box [${tableStr}] (indexed 0–F). Each byte's high and low nibbles are independently replaced: out = (S[b>>4] << 4) | S[b & 0xF].`,
        `Nibble-level S-box substitution on ${pick(BYTE_WORDS)} ${rng}. The permutation table (indices 0 through 15) is: [${tableStr}]. For each byte, apply S to both the upper and lower 4-bit halves.`,
        `Process each byte ${rng} through a nibble S-box. Table: [${tableStr}]. Split each byte into high/low nibbles, look up each in the table, recombine.`,
        `Use the substitution table [${tableStr}] on ${pick(BYTE_WORDS)} ${rng}. For byte b: output = (table[b >> 4] << 4) | table[b & 0xF].`,
      ])
      return { params: { start, end, table }, instruction }
    },
    execute(data, { start, end, table }) {
      const s = start as number, e = end as number
      const t = table as number[]
      return Uint8Array.from(data.slice(s, e), (b) =>
        (t[b >> 4] << 4) | t[b & 0xf]
      )
    },
  },

  // 9: Rolling XOR — CBC-style with IV
  {
    generate(dataLen) {
      const start = randInt(0, dataLen - 16)
      const end = randInt(start + 16, Math.min(start + 48, dataLen))
      const iv = randInt(0, 256)
      const rng = rangePhrase(start, end)
      const instruction = pick([
        `${pick(SLICE_VERBS)} ${pick(BYTE_WORDS)} ${rng}. XOR each byte with the previous output byte (CBC-style rolling XOR). The initial value (IV) is ${fmtNum(iv)}. So out[0] = in[0] ^ ${fmtNum(iv)}, out[1] = in[1] ^ out[0], and so on.`,
        `Rolling XOR over data[${fmtDec(start)}:${fmtDec(end)}] with IV = ${fmtNum(iv)}. Each output byte is the XOR of the current input byte and the previous output byte.`,
        `Apply a chained XOR to ${pick(BYTE_WORDS)} ${rng}. Start with prev = ${fmtNum(iv)}. For each byte b: output b ^ prev, then set prev = that output.`,
        `CBC-mode XOR on ${pick(BYTE_WORDS)} ${rng}, IV = ${fmtNum(iv)}. result[0] = data[${fmtDec(start)}] ^ ${fmtNum(iv)}; for i > 0: result[i] = data[${fmtDec(start)} + i] ^ result[i-1].`,
        `Feedback XOR: take ${pick(BYTE_WORDS)} ${rng}, initial previous value ${fmtNum(iv)}. Each byte XORs with the preceding output to produce the next output.`,
      ])
      return { params: { start, end, iv }, instruction }
    },
    execute(data, { start, end, iv }) {
      const s = start as number, e = end as number
      let prev = iv as number
      const result = new Uint8Array(e - s)
      for (let i = 0; i < result.length; i++) {
        result[i] = data[s + i] ^ prev
        prev = result[i]
      }
      return result
    },
  },
]

// --- Compositional pipeline ---

function composePipeline(
  t1: TransformDef,
  t2: TransformDef,
  dataLen: number
): { params1: Record<string, number | number[]>; params2: Record<string, number | number[]>; instruction: string; execute: (data: Uint8Array) => Uint8Array | Promise<Uint8Array> } {
  const g1 = t1.generate(dataLen)
  // t2 operates on the output of t1, which is variable-length.
  // We generate t2's params with a reasonable assumed output length and then
  // override its start/end to cover the full intermediate result.
  const g2Override = t2.generate(256)

  const bridge = pick([
    "Take that result and",
    "Then, on the output,",
    "Pipe the result into the next operation:",
    "Feed the output forward and",
    "Using the intermediate bytes,",
  ])

  // Strip trailing period from first instruction
  const inst1 = g1.instruction.replace(/\.\s*$/, "")
  const inst2 = g2Override.instruction.charAt(0).toLowerCase() + g2Override.instruction.slice(1)

  const instruction = `${inst1}. ${bridge} ${inst2}`

  return {
    params1: g1.params,
    params2: g2Override.params,
    instruction,
    async execute(data: Uint8Array) {
      const intermediate = await t1.execute(data, g1.params)
      // Override t2's range to cover the full intermediate output
      const p2 = { ...g2Override.params, start: 0, end: intermediate.length }
      return t2.execute(intermediate, p2)
    },
  }
}

// --- Helpers ---

function toBase64(buf: Uint8Array): string {
  let binary = ""
  for (const b of buf) binary += String.fromCharCode(b)
  return btoa(binary)
}

function concat(arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((n, a) => n + a.length, 0)
  const result = new Uint8Array(total)
  let offset = 0
  for (const a of arrays) {
    result.set(a, offset)
    offset += a.length
  }
  return result
}

// --- Challenge generator ---

export async function generateChallenge(numTransforms: number = 0) {
  if (numTransforms === 0) numTransforms = randInt(2, 4)

  const data = randomBytes(256)
  const nonce = toHex(randomBytes(16))

  const indices = [...Array(transforms.length).keys()]
  const selected: number[] = []
  for (let i = 0; i < numTransforms; i++) {
    const idx = randInt(0, indices.length)
    selected.push(indices.splice(idx, 1)[0])
  }

  const instructions: string[] = []
  const results: Uint8Array[] = []

  for (const idx of selected) {
    const t = transforms[idx]

    // ~25% chance of composing with another random transform
    if (Math.random() < 0.25 && indices.length > 0) {
      const idx2 = indices.splice(randInt(0, indices.length), 1)[0]
      const pipeline = composePipeline(t, transforms[idx2], data.length)
      instructions.push(pipeline.instruction)
      results.push(await pipeline.execute(data))
    } else {
      const { params, instruction } = t.generate(data.length)
      instructions.push(instruction)
      results.push(await t.execute(data, params))
    }
  }

  instructions.push(pick(CONCAT_FINAL)(numTransforms))

  const combined = concat(results)
  const expectedAnswer = await sha256hex(combined)

  return {
    dataB64: toBase64(data),
    nonce,
    instructions,
    expectedAnswer,
  }
}
