import * as _cryptico from "cryptico";
import * as util from "util";

export interface Type<A> extends Function {
  new (...args: any[]): A;
}

export type hex = string;
export type base64 = string;
export type ascii = string;
export type bytes = number[];
export type lines = string;

export type AESKey = bytes;

export declare namespace cryptico_ns {
  export class RSAKey {
    n; // : BigInteger;
    e; // : number;
    d; // : BigInteger;
    p; // : BigInteger;
    q; // : BigInteger;
    dmp1; // : BiquadFilterType;
    dmq1; // : BigInteger;
    coeff; // : BigInteger;

    // protected
    doPublic(x);

    // protected
    doPrivate(x);

    // public
    setPublic(N, E);

    // public
    encrypt(text: string): hex;

    // public
    setPrivate(N, E, D);

    // public
    setPrivateEx(N, E, D, P, Q, DP, DQ, C);

    // public
    generate(B, E);

    // public
    decrypt(ctext: hex): string;

    // ====================
    // Signature Generation
    // ====================

    signString(s, hashAlg);

    signStringWithSHA1(s);

    signStringWithSHA256(s);

    verifyString(sMsg, hSig);

    verifyHexSignatureForMessage(hSig, sMsg);

    // ====================
    // Serialization
    // ====================

    // public
    toJSON(): {
      coeff: string
      d: string
      dmp1: string
      dmq1: string
      e: string
      n: string
      p: string
      q: string
    };

    static parse(rsaString: string): RSAKey;
  }
}

export type RSAKey = cryptico_ns.RSAKey;

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

export interface Cryptico {
  RSAKey: Type<RSAKey> & { parse: (rawString: string) => RSAKey }

  b256to64 (t: ascii): base64;

  b64to256 (t: base64): ascii;

  b16to64 (h: hex): base64;

  b64to16 (s: base64): hex;

  string2bytes (string: ascii): bytes;

  bytes2string (bytes: bytes): ascii;

  /* all are 16-byte number array */
  blockXOR (a: bytes, b: bytes): bytes;

  /* return 16-byte number array */
  blockIV (): bytes;

  pad16 (bytes: bytes): bytes;

  depad (bytes: bytes): bytes;

  encryptAESCBC (plaintext: ascii, key: AESKey): base64;

  decryptAESCBC (encryptedText: base64, key): ascii;

  wrap60 (string: string): lines;

  generateAESKey (): AESKey;

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
