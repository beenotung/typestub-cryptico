import * as _cryptico from "cryptico";
import * as util from "util";

export class RSAKey {
  n;
  e;
  d;
  p;
  q;
  dmp1;
  dmq1;
  coeff;
}

export type Status = "success" | string;

export interface EncryptResult {
  cipher: string;
  status: Status;
}

export interface DecryptResult {
  plaintext: string;
  publicKeyString: string;
  signature: "verified" | string;
  status: Status;
}

export interface Cryptico {
  b256to64 (t);

  b64to256 (t);

  b16to64 (h);

  b64to16 (s);

  string2bytes (string);

  bytes2string (bytes);

  blockXOR (a, b);

  blockIV ();

  pad16 (bytes);

  depad (bytes);

  encryptAESCBC (plaintext, key);

  decryptAESCBC (encryptedText, key);

  wrap60 (string);

  generateAESKey ();

  generateRSAKey (passphrase: string, bitlength: number): RSAKey;

  publicKeyString (rsakey: RSAKey): string;

  publicKeyID (publicKeyString): string;

  publicKeyFromString (string: string);

  encrypt (plaintext: string, publickeystring: string, signingkey: RSAKey): EncryptResult;

  decrypt (ciphertext: string, key: RSAKey): DecryptResult;
}

const cryptico: Cryptico = _cryptico;
export default cryptico;

/* extra functions */

export function encryptRSA(plaintext: string, publickeystring: string, signingkey: RSAKey): string {
  const res = cryptico.encrypt(plaintext, publickeystring, signingkey);
  if (res.status !== "success") {
    throw new Error("Failed to encrypt: " + util.inspect(res));
  }
  return res.cipher;
}

export function decryptRSA(ciphertext: string, publickeystring: string, key: RSAKey): string {
  const res = cryptico.decrypt(ciphertext, key);
  if (res.status !== "success") {
    throw new Error("Failed to decrypt: " + util.inspect(res));
  }
  if (res.publicKeyString !== publickeystring) {
    throw new Error(`Public Key does not match! Expect: ${publickeystring}, Got: ${res.publicKeyString}`);
  }
  return res.plaintext;
}
