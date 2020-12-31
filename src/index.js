const sha = require('@voken/sha')
const crypto = require('crypto')

const ALGORITHM = 'aes-256-ctr'
// aes-128-ccm
// aes-128-gcm
// aes-192-ccm
// aes-192-gcm
// aes-256-ccm
// aes-256-gcm
// aes-256-cbc
// chacha20-poly1305

// https://www.geeksforgeeks.org/node-js-crypto-createcipheriv-method
function encrypt(data, secret) {
  if (Array.isArray(data) || data instanceof Uint8Array) { data = Buffer.from(data) }
  if (!Buffer.isBuffer(data)) { throw new TypeError('Expected Buffer') }
  if (Array.isArray(secret) || secret instanceof Uint8Array) { secret = Buffer.from(secret) }
  if (!Buffer.isBuffer(secret)) { throw new TypeError('Expected Buffer') }

  const bufHash = sha.sha384(secret)
  const cipher = crypto.createCipheriv(ALGORITHM, bufHash.slice(0, 32), bufHash.slice(32, 48));
  const encrypted = cipher.update(data);
  return Buffer.concat([encrypted, cipher.final()]);
}

// https://www.geeksforgeeks.org/node-js-crypto-createdecipheriv-method
function decrypt(data, secret) {
  if (Array.isArray(data) || data instanceof Uint8Array) { data = Buffer.from(data) }
  if (!Buffer.isBuffer(data)) { throw new TypeError('Expected Buffer') }
  if (Array.isArray(secret) || secret instanceof Uint8Array) { secret = Buffer.from(secret) }
  if (!Buffer.isBuffer(secret)) { throw new TypeError('Expected Buffer') }

  const bufHash = sha.sha384(secret)
  const decipher = crypto.createDecipheriv(ALGORITHM, bufHash.slice(0, 32), bufHash.slice(32, 48));
  const decrypted = decipher.update(data);
  return Buffer.concat([decrypted, decipher.final()]);
}

module.exports = {
  encrypt: encrypt,
  decrypt: decrypt,
}
