-- SPDX-License-Identifier: MPL-2.0
-- Copyright (c) Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
||| hpm-crypto-rsr — memory-layout proofs for the FFI boundary.
|||
||| The Zig side uses fixed-length stack buffers for its expected sizes
||| (32 bytes for HMAC-SHA256, 256 for RSA-2048). The Idris2 wrappers in
||| `Foreign.idr` only call into Zig when the buffer sizes match these
||| constants — the proofs here are the gatekeepers.

module HpmCrypto.ABI.Layout

import HpmCrypto.ABI.Types

%default total

--------------------------------------------------------------------------------
-- HMAC-SHA256 signature length
--------------------------------------------------------------------------------

||| Witness that a buffer is exactly 32 bytes (the HMAC-SHA256 output
||| size). The `Foreign.idr` wrapper takes this as a proof argument
||| rather than panicking at runtime if the caller passes a wrong-size
||| signature; the type system enforces the precondition the Zig side
||| would otherwise reject silently.
public export
data IsHmacSha256SigLen : Nat -> Type where
  ItIs32 : IsHmacSha256SigLen 32

||| Decision procedure for the same.
public export
isHmacSha256SigLen : (n : Nat) -> Dec (IsHmacSha256SigLen n)
isHmacSha256SigLen 32 = Yes ItIs32
isHmacSha256SigLen _ = No (\case _ impossible)

--------------------------------------------------------------------------------
-- Base64URL output-size bounds
--------------------------------------------------------------------------------

||| Encoded length of `n` input bytes in base64url (no padding) is
||| `ceil(n * 4 / 3)`. Used to size the output buffer the caller passes.
public export
b64uEncodedLen : (in_len : Nat) -> Nat
b64uEncodedLen n = (n * 4 + 2) `div` 3

||| Decoded length of `n` input bytes (assuming valid input) is at most
||| `floor(n * 3 / 4)`. Worst-case bound for sizing the output buffer.
public export
b64uDecodedLenBound : (in_len : Nat) -> Nat
b64uDecodedLenBound n = (n * 3) `div` 4

--------------------------------------------------------------------------------
-- RS256 (planned)
--------------------------------------------------------------------------------

||| For RSA-2048 keys, the signature is exactly 256 bytes. Larger keys
||| produce larger signatures; the Zig side rejects everything other
||| than 2048-bit until further notice (GitHub App scope).
public export
data IsRsa2048SigLen : Nat -> Type where
  ItIs256 : IsRsa2048SigLen 256

public export
isRsa2048SigLen : (n : Nat) -> Dec (IsRsa2048SigLen n)
isRsa2048SigLen 256 = Yes ItIs256
isRsa2048SigLen _ = No (\case _ impossible)
