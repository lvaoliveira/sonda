/**
 * Letters and digits that can't be mistaken for one another when a password
 * is read out or typed from a message: no 0 or O, no 1, l or I.
 */
const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'

/** Bytes at or above this are skipped, so every character is equally likely. */
const LIMIT = 256 - (256 % ALPHABET.length)

/**
 * A random password for a new user, from the browser's cryptographic random
 * source: four groups of five characters (about 117 bits), dashed so it's
 * easy to read out, such as `Kq7vM-x3TfR-9wbHc-Ne4pZ`.
 */
export function generatePassword(fill: (bytes: Uint8Array<ArrayBuffer>) => void = (b) => crypto.getRandomValues(b)): string {
  const chars: string[] = []
  while (chars.length < 20) {
    const bytes = new Uint8Array(32)
    fill(bytes)
    for (const byte of bytes) {
      if (byte < LIMIT && chars.length < 20) chars.push(ALPHABET[byte % ALPHABET.length])
    }
  }
  return [0, 5, 10, 15].map((i) => chars.slice(i, i + 5).join('')).join('-')
}
