// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
//
// hpm-crypto-rsr Zig FFI — webhook signature verification + base64url +
// (planned) RS256 JWT signing.
//
// All exports are `callconv(.C)` and have stable C signatures so the
// same .so can be consumed from Idris2 (`%foreign`), AffineScript (extern
// fn), Rust (bindgen / hand-written), and any other RSR-consumer in the
// estate.
//
// No global state; no allocator dependency; thread-safe by construction.

const std = @import("std");
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const timingSafeEql = std.crypto.timing_safe.eql;

// ============================================================================
// HMAC-SHA256 verify
// ============================================================================

/// Verify an HMAC-SHA256 signature in constant time.
///
/// Returns:
///   1  signature matches
///   0  signature mismatch (also when sig_len != 32, or any input pointer
///      is null with a non-zero length)
///  -1  unrecoverable error (currently unused — reserved)
///
/// The constant-time guarantee is provided by std.crypto.utils.timingSafeEql,
/// not by `std.mem.eql`. Do not replace.
export fn hpm_crypto_hmac_sha256_verify(
    secret_ptr: ?[*]const u8,
    secret_len: usize,
    body_ptr: ?[*]const u8,
    body_len: usize,
    sig_ptr: ?[*]const u8,
    sig_len: usize,
) c_int {
    // Wrong-length signature is a mismatch, not an error. Returning 0
    // here keeps the timing surface identical to a same-length-but-
    // wrong-bytes signature: we still compute the expected MAC, then
    // compare against a fresh zeroed buffer that the timing-safe
    // comparator treats identically.
    if (sig_len != 32) {
        // Still compute the MAC so timing stays uniform with the happy path.
        var computed: [32]u8 = undefined;
        const secret = if (secret_ptr) |p| p[0..secret_len] else "";
        const body = if (body_ptr) |p| p[0..body_len] else "";
        HmacSha256.create(&computed, body, secret);
        // Compare against zeroed buffer in constant time — always false.
        const zero: [32]u8 = @splat(0);
        _ = timingSafeEql([32]u8, computed, zero);
        return 0;
    }

    // Reject only truly null sig pointer; null secret/body with length 0
    // is valid (HMAC of empty body with empty secret is well-defined).
    if (sig_ptr == null) return 0;
    if (secret_len > 0 and secret_ptr == null) return 0;
    if (body_len > 0 and body_ptr == null) return 0;

    const secret = if (secret_ptr) |p| p[0..secret_len] else "";
    const body = if (body_ptr) |p| p[0..body_len] else "";
    const given_sig = sig_ptr.?[0..32].*;

    var computed: [32]u8 = undefined;
    HmacSha256.create(&computed, body, secret);

    return if (timingSafeEql([32]u8, computed, given_sig)) 1 else 0;
}

// ============================================================================
// Base64URL (RFC 4648 §5, no padding)
// ============================================================================

const b64u_alphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Reverse-lookup table: ASCII char -> base64url 6-bit value, or 0xFF for invalid.
const b64u_reverse: [256]u8 = blk: {
    var t: [256]u8 = @splat(0xFF);
    for (b64u_alphabet, 0..) |c, i| t[c] = @intCast(i);
    break :blk t;
};

/// Encode `in` to base64url without padding.
///
/// If out_ptr is null OR out_cap is too small, returns the required size
/// without writing. Otherwise returns the number of bytes written.
///
/// Returns -1 on null input pointer with non-zero length.
export fn hpm_crypto_base64url_encode(
    in_ptr: ?[*]const u8,
    in_len: usize,
    out_ptr: ?[*]u8,
    out_cap: usize,
) isize {
    if (in_len > 0 and in_ptr == null) return -1;

    const required = encodedLen(in_len);
    if (out_ptr == null or out_cap < required) {
        return @intCast(required);
    }

    if (in_len == 0) return 0;

    const in_slice = in_ptr.?[0..in_len];
    const out_slice = out_ptr.?[0..required];

    var i: usize = 0;
    var j: usize = 0;
    while (i + 3 <= in_len) : ({
        i += 3;
        j += 4;
    }) {
        const b0 = in_slice[i];
        const b1 = in_slice[i + 1];
        const b2 = in_slice[i + 2];
        out_slice[j] = b64u_alphabet[b0 >> 2];
        out_slice[j + 1] = b64u_alphabet[((b0 & 0x03) << 4) | (b1 >> 4)];
        out_slice[j + 2] = b64u_alphabet[((b1 & 0x0F) << 2) | (b2 >> 6)];
        out_slice[j + 3] = b64u_alphabet[b2 & 0x3F];
    }

    const rem = in_len - i;
    if (rem == 1) {
        const b0 = in_slice[i];
        out_slice[j] = b64u_alphabet[b0 >> 2];
        out_slice[j + 1] = b64u_alphabet[(b0 & 0x03) << 4];
    } else if (rem == 2) {
        const b0 = in_slice[i];
        const b1 = in_slice[i + 1];
        out_slice[j] = b64u_alphabet[b0 >> 2];
        out_slice[j + 1] = b64u_alphabet[((b0 & 0x03) << 4) | (b1 >> 4)];
        out_slice[j + 2] = b64u_alphabet[(b1 & 0x0F) << 2];
    }

    return @intCast(required);
}

/// Encoded length for `n` input bytes — `ceil(n * 4 / 3)`, no padding.
fn encodedLen(in_len: usize) usize {
    return (in_len * 4 + 2) / 3;
}

/// Decode base64url `in` to bytes.
///
/// Same size-query convention as encode. Returns -1 on any character
/// outside the base64url alphabet, OR on a structurally invalid length
/// (lengths ≡ 1 mod 4 are impossible).
export fn hpm_crypto_base64url_decode(
    in_ptr: ?[*]const u8,
    in_len: usize,
    out_ptr: ?[*]u8,
    out_cap: usize,
) isize {
    if (in_len > 0 and in_ptr == null) return -1;

    // Lengths ≡ 1 mod 4 are not reachable in unpadded base64url.
    if (in_len % 4 == 1) return -1;

    const required = decodedLen(in_len);
    if (out_ptr == null or out_cap < required) {
        return @intCast(required);
    }

    if (in_len == 0) return 0;

    const in_slice = in_ptr.?[0..in_len];
    const out_slice = out_ptr.?[0..required];

    // Validate the whole input up front so we never write partial output.
    for (in_slice) |c| {
        if (b64u_reverse[c] == 0xFF) return -1;
    }

    var i: usize = 0;
    var j: usize = 0;
    while (i + 4 <= in_len) : ({
        i += 4;
        j += 3;
    }) {
        const v0 = b64u_reverse[in_slice[i]];
        const v1 = b64u_reverse[in_slice[i + 1]];
        const v2 = b64u_reverse[in_slice[i + 2]];
        const v3 = b64u_reverse[in_slice[i + 3]];
        out_slice[j] = (v0 << 2) | (v1 >> 4);
        out_slice[j + 1] = ((v1 & 0x0F) << 4) | (v2 >> 2);
        out_slice[j + 2] = ((v2 & 0x03) << 6) | v3;
    }

    const rem = in_len - i;
    if (rem == 2) {
        const v0 = b64u_reverse[in_slice[i]];
        const v1 = b64u_reverse[in_slice[i + 1]];
        out_slice[j] = (v0 << 2) | (v1 >> 4);
    } else if (rem == 3) {
        const v0 = b64u_reverse[in_slice[i]];
        const v1 = b64u_reverse[in_slice[i + 1]];
        const v2 = b64u_reverse[in_slice[i + 2]];
        out_slice[j] = (v0 << 2) | (v1 >> 4);
        out_slice[j + 1] = ((v1 & 0x0F) << 4) | (v2 >> 2);
    }

    return @intCast(required);
}

/// Max decoded length for `n` input bytes — assumes valid input.
fn decodedLen(in_len: usize) usize {
    const rem = in_len % 4;
    const quads = in_len / 4;
    return switch (rem) {
        0 => quads * 3,
        2 => quads * 3 + 1,
        3 => quads * 3 + 2,
        else => 0, // rem == 1 is invalid; handled by caller
    };
}

// ============================================================================
// RS256 sign — TODO (see ROADMAP.adoc)
//
// Zig std as of 0.15 exposes RSA only via std.crypto.Certificate.rsa for
// signature *verification* during cert chain validation; no signing path
// is on the public API. Options:
//   (a) Hand-roll RSASSA-PKCS1-v1_5 over std.crypto.hash.sha2 + std.math.big.int
//       — bounded scope (~300 LoC, no deps), reviewable.
//   (b) Vendor a known-good Zig RSA library (zig-bored, etc.) — fewer
//       LoC to maintain but adds a dependency.
//   (c) Link against BoringSSL / OpenSSL via @cImport — operationally
//       simple but adds a runtime dep that defeats the "drop-in .so" goal.
//
// Tracking decision in ROADMAP.adoc. The exported symbol is stubbed below
// so consumers get a clear error rather than a missing-symbol link failure.
// ============================================================================

export fn hpm_crypto_rs256_sign(
    pkcs8_pem_ptr: ?[*]const u8,
    pkcs8_pem_len: usize,
    msg_ptr: ?[*]const u8,
    msg_len: usize,
    sig_out: ?[*]u8,
    sig_cap: usize,
) isize {
    _ = pkcs8_pem_ptr;
    _ = pkcs8_pem_len;
    _ = msg_ptr;
    _ = msg_len;
    _ = sig_out;
    _ = sig_cap;
    return -1; // not yet implemented
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "hmac: known-answer test (RFC 4231 test case 1)" {
    // Standard HMAC-SHA256 KAT — guards the wire encoding rather than just
    // round-trip consistency with our own implementation.
    const key = [_]u8{0x0b} ** 20;
    const data = "Hi There";
    const expected = [_]u8{
        0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
        0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
        0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
        0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7,
    };
    const rc = hpm_crypto_hmac_sha256_verify(
        &key,
        key.len,
        data.ptr,
        data.len,
        &expected,
        expected.len,
    );
    try testing.expectEqual(@as(c_int, 1), rc);
}

test "hmac: wrong signature rejected" {
    const secret = "topsecret";
    const body = "the body";
    const bad_sig = [_]u8{0xff} ** 32;
    const rc = hpm_crypto_hmac_sha256_verify(
        secret.ptr,
        secret.len,
        body.ptr,
        body.len,
        &bad_sig,
        bad_sig.len,
    );
    try testing.expectEqual(@as(c_int, 0), rc);
}

test "hmac: wrong-length signature returns 0 (mismatch, not error)" {
    const secret = "topsecret";
    const body = "the body";
    const short_sig = [_]u8{0xaa} ** 16;
    const rc = hpm_crypto_hmac_sha256_verify(
        secret.ptr,
        secret.len,
        body.ptr,
        body.len,
        &short_sig,
        short_sig.len,
    );
    try testing.expectEqual(@as(c_int, 0), rc);
}

test "hmac: empty body authenticated" {
    // RFC 4231 doesn't cover this exact case, but empty body is a legit
    // GitHub webhook (e.g. a `ping` with no payload). Just verify
    // round-trip with the same key.
    const secret = "secret";
    var computed: [32]u8 = undefined;
    HmacSha256.create(&computed, "", secret);
    const rc = hpm_crypto_hmac_sha256_verify(
        secret.ptr,
        secret.len,
        null,
        0,
        &computed,
        computed.len,
    );
    try testing.expectEqual(@as(c_int, 1), rc);
}

test "hmac: null sig pointer rejected" {
    const secret = "secret";
    const body = "body";
    const rc = hpm_crypto_hmac_sha256_verify(
        secret.ptr,
        secret.len,
        body.ptr,
        body.len,
        null,
        32, // length is 32 but pointer is null
    );
    try testing.expectEqual(@as(c_int, 0), rc);
}

test "b64u encode: empty input" {
    const rc = hpm_crypto_base64url_encode(null, 0, null, 0);
    try testing.expectEqual(@as(isize, 0), rc);
}

test "b64u encode: known fixture (JWT header)" {
    const input = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
    const expected = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9";
    var out: [64]u8 = undefined;
    const rc = hpm_crypto_base64url_encode(input.ptr, input.len, &out, out.len);
    try testing.expectEqual(@as(isize, @intCast(expected.len)), rc);
    try testing.expectEqualStrings(expected, out[0..@intCast(rc)]);
}

test "b64u encode: size query (null out)" {
    const input = "hello world";
    const rc = hpm_crypto_base64url_encode(input.ptr, input.len, null, 0);
    // ceil(11 * 4 / 3) = 15
    try testing.expectEqual(@as(isize, 15), rc);
}

test "b64u encode: '+' / '/' rewritten to '-' / '_'" {
    // Stock base64 ">>>>" is "Pj4+Pg==". base64url should be "Pj4-Pg".
    const input = ">>>>";
    const expected = "Pj4-Pg";
    var out: [16]u8 = undefined;
    const rc = hpm_crypto_base64url_encode(input.ptr, input.len, &out, out.len);
    try testing.expectEqual(@as(isize, @intCast(expected.len)), rc);
    try testing.expectEqualStrings(expected, out[0..@intCast(rc)]);
}

test "b64u decode: empty input" {
    const rc = hpm_crypto_base64url_decode(null, 0, null, 0);
    try testing.expectEqual(@as(isize, 0), rc);
}

test "b64u decode: JWT header round-trip" {
    const input = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9";
    const expected = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
    var out: [64]u8 = undefined;
    const rc = hpm_crypto_base64url_decode(input.ptr, input.len, &out, out.len);
    try testing.expectEqual(@as(isize, @intCast(expected.len)), rc);
    try testing.expectEqualStrings(expected, out[0..@intCast(rc)]);
}

test "b64u decode: invalid character rejected" {
    const input = "Pj4!Pg"; // '!' is not in the alphabet
    var out: [16]u8 = undefined;
    const rc = hpm_crypto_base64url_decode(input.ptr, input.len, &out, out.len);
    try testing.expectEqual(@as(isize, -1), rc);
}

test "b64u decode: invalid length (≡ 1 mod 4) rejected" {
    const input = "A"; // 1 char input is structurally impossible
    var out: [16]u8 = undefined;
    const rc = hpm_crypto_base64url_decode(input.ptr, input.len, &out, out.len);
    try testing.expectEqual(@as(isize, -1), rc);
}

test "b64u decode: stock-base64 '+' is rejected" {
    // The whole point of base64url is the alphabet swap. A '+' input
    // should fail-closed rather than silently being treated as '-'.
    const input = "Pj4+Pg";
    var out: [16]u8 = undefined;
    const rc = hpm_crypto_base64url_decode(input.ptr, input.len, &out, out.len);
    try testing.expectEqual(@as(isize, -1), rc);
}

test "b64u decode: 7-char round-trip via encode" {
    const original = "SGVsbG8";
    var decoded: [8]u8 = undefined;
    const dlen = hpm_crypto_base64url_decode(original.ptr, original.len, &decoded, decoded.len);
    try testing.expect(dlen > 0);

    var re_encoded: [16]u8 = undefined;
    const elen = hpm_crypto_base64url_encode(&decoded, @intCast(dlen), &re_encoded, re_encoded.len);
    try testing.expectEqualStrings(original, re_encoded[0..@intCast(elen)]);
}

test "rs256_sign returns -1 (not yet implemented)" {
    const rc = hpm_crypto_rs256_sign(null, 0, null, 0, null, 0);
    try testing.expectEqual(@as(isize, -1), rc);
}
