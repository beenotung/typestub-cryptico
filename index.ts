import * as _cryptico from "cryptico";

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

  decrypt (ciphertext: string, key): DecryptResult;
}

const cryptico: Cryptico = _cryptico;
export default cryptico;
