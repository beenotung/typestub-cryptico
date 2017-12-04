import * as _cryptico from "cryptico";

export interface Type<A> extends Function {
  new (...args: any[]): A;
}

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
    encrypt(text);

    // public
    setPrivate(N, E, D);

    // public
    setPrivateEx(N, E, D, P, Q, DP, DQ, C);

    // public
    generate(B, E);

    // public
    decrypt(ctext);

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

export declare function encryptRSA(plaintext: string, publickeystring: string, signingkey: cryptico_ns.RSAKey): string;

export declare function decryptRSA(ciphertext: string, publickeystring: string, key: cryptico_ns.RSAKey): string;

export interface Cryptico {
  RSAKey: Type<cryptico_ns.RSAKey>

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

  publicKeyString (rsakey: cryptico_ns.RSAKey) ;

  publicKeyID (publicKeyString);

  publicKeyFromString (string);

  encrypt (plaintext, publickeystring, signingkey);

  decrypt (ciphertext, key);
}

const cryptico: Cryptico = _cryptico;
export default cryptico;
export let RSAKey = cryptico.RSAKey;
