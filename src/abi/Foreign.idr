||| hpm-crypto-rsr — %foreign declarations binding into libhpm_crypto.so.
|||
||| Every external Zig export gets a private `prim__*` `%foreign`
||| declaration, then a safe Idris2 wrapper that enforces the layout
||| proofs from `HpmCrypto.ABI.Layout` and returns a typed outcome from
||| `HpmCrypto.ABI.Types` rather than a raw C `Int`.

module HpmCrypto.ABI.Foreign

import Data.Buffer
import HpmCrypto.ABI.Types
import HpmCrypto.ABI.Layout

%default total

--------------------------------------------------------------------------------
-- HMAC-SHA256 verify
--------------------------------------------------------------------------------

||| Raw C call.
|||
|||   int hpm_crypto_hmac_sha256_verify(
|||       const uint8_t* secret_ptr, size_t secret_len,
|||       const uint8_t* body_ptr,   size_t body_len,
|||       const uint8_t* sig_ptr,    size_t sig_len);
|||
||| Returns 1 on match, 0 on mismatch (including wrong length), -1 on
||| null-pointer error.
%foreign "C:hpm_crypto_hmac_sha256_verify, libhpm_crypto"
prim__hmacSha256Verify : Buffer -> Int -> Buffer -> Int -> Buffer -> Int -> PrimIO Int

||| Verify an HMAC-SHA256 signature in constant time.
|||
||| The `sigLenProof` argument forces the caller to confirm the signature
||| is the right length at the *type* level; a wrong-length signature
||| would always mismatch on the C side, but rejecting it here gives a
||| clearer error path and avoids a useless FFI round-trip.
export
hmacSha256Verify :
     (secret : Buffer)
  -> (secretLen : Int)
  -> (body : Buffer)
  -> (bodyLen : Int)
  -> (sig : Buffer)
  -> (sigLen : Nat)
  -> {auto 0 sigLenProof : IsHmacSha256SigLen sigLen}
  -> IO HmacResult
hmacSha256Verify secret sLen body bLen sig sigLen = do
  rc <- primIO $ prim__hmacSha256Verify secret sLen body bLen sig (cast sigLen)
  pure (hmacResultFromInt rc)

--------------------------------------------------------------------------------
-- Base64URL encode
--------------------------------------------------------------------------------

||| Raw C call.
|||
|||   ssize_t hpm_crypto_base64url_encode(
|||       const uint8_t* in_ptr,  size_t in_len,
|||       uint8_t* out_ptr,       size_t out_cap);
|||
||| When `out_ptr` is null (and `out_cap` is 0) the function returns the
||| required size without writing. Otherwise returns bytes written or -1.
%foreign "C:hpm_crypto_base64url_encode, libhpm_crypto"
prim__b64uEncode : Buffer -> Int -> Buffer -> Int -> PrimIO Int

||| Base64URL encode (RFC 4648 §5, no padding). `out` must have
||| capacity ≥ `b64uEncodedLen (cast inLen)`.
export
base64UrlEncode :
     (in_ : Buffer)
  -> (inLen : Int)
  -> (out : Buffer)
  -> (outCap : Int)
  -> IO B64uResult
base64UrlEncode in_ inLen out outCap = do
  rc <- primIO $ prim__b64uEncode in_ inLen out outCap
  pure (b64uResultFromInt rc)

--------------------------------------------------------------------------------
-- Base64URL decode
--------------------------------------------------------------------------------

||| Raw C call. Same shape as encode.
|||
|||   ssize_t hpm_crypto_base64url_decode(
|||       const uint8_t* in_ptr,  size_t in_len,
|||       uint8_t* out_ptr,       size_t out_cap);
%foreign "C:hpm_crypto_base64url_decode, libhpm_crypto"
prim__b64uDecode : Buffer -> Int -> Buffer -> Int -> PrimIO Int

||| Base64URL decode. Returns `B64uError` on any non-alphabet character.
export
base64UrlDecode :
     (in_ : Buffer)
  -> (inLen : Int)
  -> (out : Buffer)
  -> (outCap : Int)
  -> IO B64uResult
base64UrlDecode in_ inLen out outCap = do
  rc <- primIO $ prim__b64uDecode in_ inLen out outCap
  pure (b64uResultFromInt rc)

--------------------------------------------------------------------------------
-- RS256 sign (declared; Zig implementation TODO — see ROADMAP.adoc)
--------------------------------------------------------------------------------

||| Planned. Once implemented in Zig:
|||
|||   ssize_t hpm_crypto_rs256_sign(
|||       const uint8_t* pkcs8_pem_ptr, size_t pkcs8_pem_len,
|||       const uint8_t* msg_ptr,       size_t msg_len,
|||       uint8_t* sig_out,             size_t sig_cap);
|||
||| Until the Zig side lands, calling this aborts with a clear error.
%foreign "C:hpm_crypto_rs256_sign, libhpm_crypto"
prim__rs256Sign : Buffer -> Int -> Buffer -> Int -> Buffer -> Int -> PrimIO Int

export
rs256Sign :
     (pkcs8Pem : Buffer)
  -> (pkcs8PemLen : Int)
  -> (msg : Buffer)
  -> (msgLen : Int)
  -> (sigOut : Buffer)
  -> (sigCap : Int)
  -> IO B64uResult
rs256Sign pem pLen msg mLen out cap = do
  rc <- primIO $ prim__rs256Sign pem pLen msg mLen out cap
  pure (b64uResultFromInt rc)
