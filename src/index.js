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
function encrypt(bufData, secret) {
  const bufSecret = Buffer.isBuffer(secret) ? secret : Buffer.from(secret)
  const bufHash = sha.sha384(bufSecret)
  const cipher = crypto.createCipheriv(ALGORITHM, bufHash.slice(0, 32), bufHash.slice(32, 48));
  const encrypted = cipher.update(bufData);
  return Buffer.concat([encrypted, cipher.final()]);
}

// https://www.geeksforgeeks.org/node-js-crypto-createdecipheriv-method
function decrypt(bufData, secret) {
  const bufSecret = Buffer.isBuffer(secret) ? secret : Buffer.from(secret)
  const bufHash = sha.sha384(bufSecret)
  const decipher = crypto.createDecipheriv(ALGORITHM, bufHash.slice(0, 32), bufHash.slice(32, 48));
  const decrypted = decipher.update(bufData);
  return Buffer.concat([decrypted, decipher.final()]);
}

module.exports = {
  encrypt: encrypt,
  decrypt: decrypt
}
