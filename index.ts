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

export declare type Status = "success" | string;

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

export declare function encryptRSA(plaintext: string, publickeystring: string, signingkey: RSAKey): string;

export declare function decryptRSA(ciphertext: string, publickeystring: string, key: RSAKey): string;

export interface Cryptico {
  b256to64 (t) ;

  b64to256 (t) ;

  b16to64 (h) ;

  b64to16 (s) ;

  string2bytes (string);

  bytes2string (bytes);

  blockXOR (a, b);

  blockIV ();

  pad16 (bytes);

  depad (bytes);

  encryptAESCBC (plaintext, key);

  decryptAESCBC (encryptedText, key);

  wrap60 (string) ;

  generateAESKey ();

  generateRSAKey (passphrase: string, bitlength: number);

  publicKeyString (rsakey: RSAKey) ;

  publicKeyID (publicKeyString);

  publicKeyFromString (string);

  encrypt (plaintext, publickeystring, signingkey);

  decrypt (ciphertext, key);
}

const cryptico: Cryptico = _cryptico;
export default cryptico;
