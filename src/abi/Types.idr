-- SPDX-License-Identifier: MPL-2.0
-- Copyright (c) Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
||| hpm-crypto-rsr — type declarations for the FFI boundary.
|||
||| Every type that crosses the C ABI is declared here so the Idris2
||| wrappers in `Foreign.idr` have a single source of truth and so the
||| C header generator can emit matching `typedef`s.

module HpmCrypto.ABI.Types

import Data.Buffer

%default total

--------------------------------------------------------------------------------
-- Result codes returned by C functions
--------------------------------------------------------------------------------

||| HMAC verify outcomes. Mirrors the Zig `int` return:
|||   1  = signature matches
|||   0  = signature mismatch (or wrong length, or null inputs)
|||  -1  = unrecoverable error (e.g. truly null output pointer)
public export
data HmacResult : Type where
  Matches : HmacResult
  Mismatches : HmacResult
  HmacError : HmacResult

public export
hmacResultFromInt : Int -> HmacResult
hmacResultFromInt 1 = Matches
hmacResultFromInt 0 = Mismatches
hmacResultFromInt _ = HmacError

||| Base64url encode/decode outcome. The Zig side returns the number of
||| bytes written, or -1 on error (decode hit an illegal character, or a
||| null pointer with a non-zero length).
public export
data B64uResult : Type where
  B64uOk : (bytesWritten : Nat) -> B64uResult
  B64uError : B64uResult

public export
b64uResultFromInt : Int -> B64uResult
b64uResultFromInt n =
  if n < 0
    then B64uError
    else B64uOk (cast n)

--------------------------------------------------------------------------------
-- Size constants
--------------------------------------------------------------------------------

||| HMAC-SHA256 produces a 32-byte (256-bit) MAC. The Zig FFI rejects
||| any other length without a timing leak (returns Mismatches).
public export
HmacSha256SigLen : Nat
HmacSha256SigLen = 32

||| RSA-2048 produces a 256-byte signature. Other modulus sizes (1024,
||| 3072, 4096) are valid RS256 keys but not in the bot's threat model —
||| GitHub Apps issue 2048-bit keys. Documented for future-proofing.
public export
Rs256_2048_SigLen : Nat
Rs256_2048_SigLen = 256

--------------------------------------------------------------------------------
-- Opaque key handle (placeholder until RS256 lands)
--------------------------------------------------------------------------------

||| A parsed PKCS#8 RSA private key, post-PEM-decode + DER-parse. The
||| Idris2 side never inspects its representation; it's a token passed
||| from `parse_pkcs8` to `rs256_sign`. The actual struct lives in Zig.
|||
||| When RS256 lands, this will be backed by an `AnyPtr` to a
||| heap-allocated Zig record. Until then it's a stub to keep the
||| Foreign.idr signatures stable.
public export
data Pkcs8Key : Type where
  MkPkcs8Key : AnyPtr -> Pkcs8Key

export
unsafeRawHandle : Pkcs8Key -> AnyPtr
unsafeRawHandle (MkPkcs8Key p) = p
