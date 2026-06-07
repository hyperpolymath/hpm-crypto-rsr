<!--
SPDX-License-Identifier: MPL-2.0
Copyright (c) Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
-->
<!-- SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk> -->

# hpm-crypto-rsr ABI/FFI Documentation

## Overview

This library follows the **Hyperpolymath RSR Standard** for ABI and FFI design:

- **ABI (Application Binary Interface)** defined in **Idris2** with safety proofs
- **FFI (Foreign Function Interface)** implemented in **Zig** for C compatibility
- **Generated C headers** bridge Idris2 ABI to Zig FFI
- **Any language** can call through standard C ABI

## Architecture

```
┌─────────────────────────────────────────────┐
│  ABI Definitions (Idris2)                   │
│  src/abi/                                   │
│  - Types.idr     (Type definitions)         │
│  - Layout.idr    (Memory layout proofs)     │
│  - Foreign.idr   (FFI declarations)         │
└─────────────────┬───────────────────────────┘
                  │
                  │ generates (at compile time)
                  ▼
┌─────────────────────────────────────────────┐
│  C Headers (auto-generated)                 │
│  generated/abi/hpm_crypto.h                 │
└─────────────────┬───────────────────────────┘
                  │
                  │ imported by
                  ▼
┌─────────────────────────────────────────────┐
│  FFI Implementation (Zig)                   │
│  ffi/zig/src/main.zig                       │
│  - Implements C-compatible functions        │
│  - Uses std.crypto.auth.hmac.sha2 + hand-   │
│    rolled base64url                         │
│  - Memory-safe by default (Zig)             │
└─────────────────┬───────────────────────────┘
                  │
                  │ compiled to libhpm_crypto.so/.a
                  ▼
┌─────────────────────────────────────────────┐
│  Any Language via C ABI                     │
│  - AffineScript, Rust, Idris2, Julia, etc.  │
└─────────────────────────────────────────────┘
```

## Directory Structure

```
hpm-crypto-rsr/
├── src/
│   ├── abi/                    # ABI definitions (Idris2)
│   │   ├── Types.idr           # Core type definitions with proofs
│   │   ├── Layout.idr          # Memory layout verification
│   │   └── Foreign.idr         # FFI function declarations
│   └── HpmCrypto.idr           # High-level Idris2 API (safe wrappers)
├── ffi/
│   └── zig/
│       ├── build.zig           # Zig build configuration
│       ├── src/
│       │   └── main.zig        # Zig FFI implementation
│       └── test/
│           └── integration_test.zig
├── generated/
│   └── abi/
│       └── hpm_crypto.h        # Generated C header
├── docs/
└── examples/
```

## Function-by-function contract

### HMAC-SHA256 verification

```c
// Returns: 1 if signature matches, 0 if mismatch, -1 on null pointer error
int hpm_crypto_hmac_sha256_verify(
    const uint8_t* secret_ptr, size_t secret_len,
    const uint8_t* body_ptr,   size_t body_len,
    const uint8_t* sig_ptr,    size_t sig_len   // must be 32
);
```

- **Constant-time** comparison via `std.crypto.utils.timingSafeEql`.
- `sig_len != 32` returns 0 (mismatch) without timing leak.
- Empty body (`body_len == 0`) is valid and authenticated.

### base64url encode / decode (RFC 4648 §5, no padding)

```c
// Returns: number of bytes written to out_ptr (or required if out_cap == 0),
//          or -1 on error.
// Caller pattern: call with out_cap = 0 to query size, allocate, call again.
ssize_t hpm_crypto_base64url_encode(
    const uint8_t* in_ptr,  size_t in_len,
    uint8_t* out_ptr,       size_t out_cap
);

ssize_t hpm_crypto_base64url_decode(
    const uint8_t* in_ptr,  size_t in_len,
    uint8_t* out_ptr,       size_t out_cap
);
```

- Output size for encode: `ceil(in_len * 4 / 3)` (no padding).
- Output size for decode: at most `(in_len * 3 + 3) / 4`.
- Decode returns -1 on invalid character (anything outside `[A-Za-z0-9_-]`).

### RS256 sign (planned, not yet implemented)

```c
// Returns: number of bytes written (= modulus length, typically 256 for RSA-2048),
//          or -1 on error.
ssize_t hpm_crypto_rs256_sign(
    const uint8_t* pkcs8_pem_ptr, size_t pkcs8_pem_len,
    const uint8_t* msg_ptr,       size_t msg_len,
    uint8_t* sig_out,             size_t sig_cap
);
```

## Memory model

- All buffer parameters are caller-owned. Functions never allocate.
- Null pointers are rejected with explicit error returns, never UB.
- Output buffers must have `out_cap` large enough for the result; functions
  return the required size when `out_ptr == NULL` so callers can size-query.

## Calling-convention guarantees

- `extern fn ... callconv(.C)` on all exports.
- No global state.
- Thread-safe by construction (no shared mutable state).
- No allocator dependency.

## Safety proofs (Idris2 side)

`src/abi/Layout.idr` carries:

- `HmacSha256SigLen : 32` — type-level constant matching the Zig export's
  expected `sig_len`.
- `Base64UrlExpansion : (in_len : Nat) -> ...` — provable output size bound.
- (Planned) `Rs256ModulusLen : (key : Pkcs8Key) -> Nat` — type-level
  modulus extraction once RS256 lands.

These are not just decoration: the safe Idris2 wrappers in `Foreign.idr`
refuse to call into the Zig layer with sizes that violate the proofs.
