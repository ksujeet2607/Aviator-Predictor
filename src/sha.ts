import { sha_variant_error } from "./common";
import {
  CSHAKEOptionsEncodingType,
  CSHAKEOptionsNoEncodingType,
  SHAKEOptionsEncodingType,
  SHAKEOptionsNoEncodingType,
  EncodingType,
  formating,
  FixedLengthOptionsEncodingType,
  FixedLengthOptionsNoEncodingType,
  FormatNoTextType,
  KMACOptionsNoEncodingType,
  KMACOptionsEncodingType,
} from "./custom_types";
import jsSHA1 from "./sha1";
import jsSHA256 from "./sha256";
import jsSHA512 from "./sha512";
import jsSHA3 from "./sha3";

type FixedLengthVariantType =
  | "SHA-1"
  | "SHA-224"
  | "SHA-256"
  | "SHA-384"
  | "SHA-512"
  | "SHA3-224"
  | "SHA3-256"
  | "SHA3-384"
  | "SHA3-512";

export default class jsSHA {
  private readonly shaObj: jsSHA1 | jsSHA256 | jsSHA512 | jsSHA3;

  /**
   * Creates a new SHA hash instance
   * @param variant The desired SHA variant (SHA-1, SHA-224, SHA-256, SHA-384, SHA-512,
   *   SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, SHAKE256, CSHAKE128, CSHAKE256,
   *   KMAC128, or KMAC256)
   * @param inputFormat The format for input data (TEXT, HEX, B64, BYTES, ARRAYBUFFER, UINT8ARRAY)
   * @param options Additional settings like encoding, number of rounds, or keys
   */
  constructor(variant: FixedLengthVariantType, inputFormat: "TEXT", options?: FixedLengthOptionsEncodingType);
  constructor(
    variant: FixedLengthVariantType,
    inputFormat: FormatNoTextType,
    options?: FixedLengthOptionsNoEncodingType
  );
  constructor(variant: "SHAKE128" | "SHAKE256", inputFormat: "TEXT", options?: SHAKEOptionsEncodingType);
  constructor(variant: "SHAKE128" | "SHAKE256", inputFormat: FormatNoTextType, options?: SHAKEOptionsNoEncodingType);
  constructor(variant: "CSHAKE128" | "CSHAKE256", inputFormat: "TEXT", options?: CSHAKEOptionsEncodingType);
  constructor(variant: "CSHAKE128" | "CSHAKE256", inputFormat: FormatNoTextType, options?: CSHAKEOptionsNoEncodingType);
  constructor(variant: "KMAC128" | "KMAC256", inputFormat: "TEXT", options: KMACOptionsEncodingType);
  constructor(variant: "KMAC128" | "KMAC256", inputFormat: FormatNoTextType, options: KMACOptionsNoEncodingType);

  // Implementation
  constructor(variant: any, inputFormat: any, options?: any) {
    // Variant groups for quick membership checks
    const SHA1_VARIANTS = new Set(["SHA-1"]);
    const SHA256_VARIANTS = new Set(["SHA-224", "SHA-256"]);
    const SHA512_VARIANTS = new Set(["SHA-384", "SHA-512"]);
    const SHA3_VARIANTS = new Set(["SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512"]);
    const XOF_AND_KMAC_VARIANTS = new Set([
      "SHAKE128",
      "SHAKE256",
      "CSHAKE128",
      "CSHAKE256",
      "KMAC128",
      "KMAC256",
    ]);

    if (SHA1_VARIANTS.has(variant)) {
      this.shaObj = new jsSHA1(variant, inputFormat, options);
      return;
    }

    if (SHA256_VARIANTS.has(variant)) {
      this.shaObj = new jsSHA256(variant, inputFormat, options);
      return;
    }

    if (SHA512_VARIANTS.has(variant)) {
      this.shaObj = new jsSHA512(variant, inputFormat, options);
      return;
    }

    if (SHA3_VARIANTS.has(variant) || XOF_AND_KMAC_VARIANTS.has(variant)) {
      // jsSHA3 handles SHA3 family, XOFs (SHAKE/CSHAKE) and KMAC variants
      this.shaObj = new jsSHA3(variant, inputFormat, options);
      return;
    }

    throw new Error(sha_variant_error);
  }

  /**
   * Update the internal hash state with more data.
   * Accepts strings, ArrayBuffer, Uint8Array or any ArrayBufferView.
   */
  update(input: string | ArrayBuffer | Uint8Array | ArrayBufferView): this {
    // delegate to inner implementation
    // jsSHA implementations accept the same shapes; if not, they will throw appropriately
    (this.shaObj as any).update(input);
    return this;
  }

  // getHash overloads
  getHash(format: "HEX", options?: { outputUpper?: boolean; outputLen?: number; shakeLen?: number }): string;
  getHash(format: "B64", options?: { b64Pad?: string; outputLen?: number; shakeLen?: number }): string;
  getHash(format: "BYTES", options?: { outputLen?: number; shakeLen?: number }): string;
  getHash(format: "UINT8ARRAY", options?: { outputLen?: number; shakeLen?: number }): Uint8Array;
  getHash(format: "ARRAYBUFFER", options?: { outputLen?: number; shakeLen?: number }): ArrayBuffer;
  getHash(format: any, options?: any): any {
    return (this.shaObj as any).getHash(format, options);
  }

  // setHMACKey overloads
  setHMACKey(key: string, inputFormat: "TEXT", options?: { encoding?: EncodingType }): void;
  setHMACKey(key: string, inputFormat: "B64" | "HEX" | "BYTES"): void;
  setHMACKey(key: ArrayBuffer, inputFormat: "ARRAYBUFFER"): void;
  setHMACKey(key: Uint8Array, inputFormat: "UINT8ARRAY"): void;
  setHMACKey(key: any, inputFormat: any, options?: any): void {
    (this.shaObj as any).setHMACKey(key, inputFormat, options);
  }

  // getHMAC overloads
  getHMAC(format: "HEX", options?: { outputUpper?: boolean }): string;
  getHMAC(format: "B64", options?: { b64Pad?: string }): string;
  getHMAC(format: "BYTES"): string;
  getHMAC(format: "UINT8ARRAY"): Uint8Array;
  getHMAC(format: "ARRAYBUFFER"): ArrayBuffer;
  getHMAC(format: any, options?: any): any {
    return (this.shaObj as any).getHMAC(format, options);
  }
}
