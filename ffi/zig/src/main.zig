// SPDX-License-Identifier: MPL-2.0
// Copyright (c) Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
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
const Sha256 = std.crypto.hash.sha2.Sha256;
const timingSafeEql = std.crypto.timing_safe.eql;
const M2048 = std.crypto.ff.Modulus(2048);

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
// RS256 sign / verify (RSASSA-PKCS1-v1_5 with SHA-256, RSA-2048)
//
// Implementation strategy: hand-rolled atop std.crypto.ff (Modulus, Fe,
// powWithEncodedExponent) + std.crypto.hash.sha2.Sha256. No allocator
// dependency; all work proceeds in fixed-size stack buffers.
//
// Supported key size: RSA-2048 only (signatures are 256 bytes). Other
// sizes (3072 / 4096) are explicit future work — they require their own
// Modulus(bits) instantiation since the bit width is comptime.
//
// Input format: PKCS#8 unencrypted ("-----BEGIN PRIVATE KEY-----") only.
// PKCS#1 PEMs ("-----BEGIN RSA PRIVATE KEY-----") are rejected at the
// boundary; consumers should convert with `openssl pkcs8 -topk8`.
// ============================================================================

// RFC 8017 §9.2: DigestInfo for SHA-256.
// SEQUENCE { SEQUENCE { OID 2.16.840.1.101.3.4.2.1 (sha-256), NULL },
//            OCTET STRING (32) }
const sha256_digest_info_prefix = [_]u8{
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
};

// Standard base64 (RFC 4648 §4) — PEM body alphabet. Distinct from the
// base64url alphabet above: '+' '/' '=' rather than '-' '_' (no padding).
const stdb64_alphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const stdb64_reverse: [256]u8 = blk: {
    var t: [256]u8 = @splat(0xFF);
    for (stdb64_alphabet, 0..) |c, i| t[c] = @intCast(i);
    break :blk t;
};

const Pkcs8Error = error{
    BadPem,
    BadBase64,
    BadDer,
    UnsupportedKey,
    BufferTooSmall,
};

/// Decode a PEM body into `out`. Tolerates ASCII whitespace; requires
/// '=' padding to align to 4-char groups.
fn stdb64DecodeLenient(in: []const u8, out: []u8) Pkcs8Error!usize {
    var buf: [4]u8 = undefined;
    var bp: usize = 0;
    var op: usize = 0;
    var pads: usize = 0;
    for (in) |c| {
        switch (c) {
            ' ', '\t', '\r', '\n' => continue,
            '=' => {
                pads += 1;
                if (pads > 2) return error.BadBase64;
                buf[bp] = 0;
                bp += 1;
            },
            else => {
                if (pads != 0) return error.BadBase64;
                const v = stdb64_reverse[c];
                if (v == 0xFF) return error.BadBase64;
                buf[bp] = v;
                bp += 1;
            },
        }
        if (bp == 4) {
            const out_bytes: usize = switch (pads) {
                0 => 3,
                1 => 2,
                2 => 1,
                else => unreachable,
            };
            if (op + out_bytes > out.len) return error.BufferTooSmall;
            out[op] = (buf[0] << 2) | (buf[1] >> 4);
            if (out_bytes >= 2) out[op + 1] = ((buf[1] & 0x0F) << 4) | (buf[2] >> 2);
            if (out_bytes >= 3) out[op + 2] = ((buf[2] & 0x03) << 6) | buf[3];
            op += out_bytes;
            bp = 0;
        }
    }
    if (bp != 0) return error.BadBase64;
    return op;
}

const DerCursor = struct {
    buf: []const u8,
    i: usize,

    fn ensure(self: *DerCursor, n: usize) Pkcs8Error!void {
        if (self.i + n > self.buf.len) return error.BadDer;
    }

    fn readByte(self: *DerCursor) Pkcs8Error!u8 {
        try self.ensure(1);
        const b = self.buf[self.i];
        self.i += 1;
        return b;
    }

    fn expectTag(self: *DerCursor, tag: u8) Pkcs8Error!void {
        const got = try self.readByte();
        if (got != tag) return error.BadDer;
    }

    /// ASN.1 DER length: short form (≤127) or long form (0x80|n followed
    /// by n bytes, big-endian). We cap at 4 length-bytes — plenty for
    /// any RSA key < 4 GiB.
    fn readLen(self: *DerCursor) Pkcs8Error!usize {
        const b0 = try self.readByte();
        if (b0 < 0x80) return b0;
        const nbytes: usize = b0 & 0x7F;
        if (nbytes == 0 or nbytes > 4) return error.BadDer;
        try self.ensure(nbytes);
        var len: usize = 0;
        var j: usize = 0;
        while (j < nbytes) : (j += 1) {
            len = (len << 8) | self.buf[self.i + j];
        }
        self.i += nbytes;
        return len;
    }

    fn readBytes(self: *DerCursor, n: usize) Pkcs8Error![]const u8 {
        try self.ensure(n);
        const slice = self.buf[self.i .. self.i + n];
        self.i += n;
        return slice;
    }

    /// Read an INTEGER, returning content with any single leading 0x00
    /// stripped (DER sign-bit convention for unsigned values).
    fn readInteger(self: *DerCursor) Pkcs8Error![]const u8 {
        try self.expectTag(0x02);
        const n = try self.readLen();
        const body = try self.readBytes(n);
        if (body.len > 1 and body[0] == 0x00) return body[1..];
        return body;
    }

    fn readSequence(self: *DerCursor) Pkcs8Error!DerCursor {
        try self.expectTag(0x30);
        const n = try self.readLen();
        const body = try self.readBytes(n);
        return DerCursor{ .buf = body, .i = 0 };
    }

    fn readOctetString(self: *DerCursor) Pkcs8Error![]const u8 {
        try self.expectTag(0x04);
        const n = try self.readLen();
        return try self.readBytes(n);
    }
};

const Pkcs8Parsed = struct {
    n: []const u8,
    e: []const u8,
    d: []const u8,
};

const pem_begin = "-----BEGIN PRIVATE KEY-----";
const pem_end = "-----END PRIVATE KEY-----";

/// Parse a PKCS#8 unencrypted RSA-2048 private key. Returned slices
/// point into `scratch`, which must remain live for the caller's use.
fn parsePkcs8Pem(pem: []const u8, scratch: []u8) Pkcs8Error!Pkcs8Parsed {
    const begin = std.mem.indexOf(u8, pem, pem_begin) orelse return error.BadPem;
    const after_begin = begin + pem_begin.len;
    const end = std.mem.indexOfPos(u8, pem, after_begin, pem_end) orelse return error.BadPem;

    const der_len = try stdb64DecodeLenient(pem[after_begin..end], scratch);
    const der = scratch[0..der_len];

    var outer = DerCursor{ .buf = der, .i = 0 };
    var pki = try outer.readSequence();

    // PrivateKeyInfo.version (0)
    const version = try pki.readInteger();
    if (version.len != 1 or version[0] != 0) return error.UnsupportedKey;

    // PrivateKeyInfo.privateKeyAlgorithm — accept any; mis-match falls
    // out in the inner RSAPrivateKey shape check.
    _ = try pki.readSequence();

    // PrivateKeyInfo.privateKey OCTET STRING containing RSAPrivateKey
    const priv_der = try pki.readOctetString();

    var pk = DerCursor{ .buf = priv_der, .i = 0 };
    var rsa = try pk.readSequence();

    const rsa_version = try rsa.readInteger();
    if (rsa_version.len != 1 or rsa_version[0] != 0) return error.UnsupportedKey;

    const n = try rsa.readInteger();
    const e = try rsa.readInteger();
    const d = try rsa.readInteger();

    if (n.len != 256) return error.UnsupportedKey;

    return Pkcs8Parsed{ .n = n, .e = e, .d = d };
}

/// Build the PKCS#1 v1.5 encoded message (EM) for SHA-256(msg) into the
/// 256-byte output buffer. RFC 8017 §9.2:
///   EM = 0x00 || 0x01 || PS || 0x00 || T
///   PS = (k - 3 - tLen) bytes of 0xFF, here 256 - 3 - 51 = 202
///   T  = DigestInfo prefix (19 B) || hash (32 B)
fn buildEmSha256(msg: []const u8, em: *[256]u8) void {
    var hash: [32]u8 = undefined;
    Sha256.hash(msg, &hash, .{});
    em[0] = 0x00;
    em[1] = 0x01;
    @memset(em[2..204], 0xFF);
    em[204] = 0x00;
    @memcpy(em[205..224], &sha256_digest_info_prefix);
    @memcpy(em[224..256], &hash);
}

/// RSASSA-PKCS1-v1_5 sign with SHA-256, RSA-2048.
///
/// Returns:
///    n>0  signature length written to sig_out (always 256 on success)
///    256  size-query reply when sig_out is null or sig_cap < 256
///         (the caller should retry with a sufficient buffer)
///    -1   bad PEM, unsupported key size, math failure, or any null
///         pointer with a non-zero length
export fn hpm_crypto_rs256_sign(
    pkcs8_pem_ptr: ?[*]const u8,
    pkcs8_pem_len: usize,
    msg_ptr: ?[*]const u8,
    msg_len: usize,
    sig_out: ?[*]u8,
    sig_cap: usize,
) isize {
    if (sig_out == null or sig_cap < 256) return 256;
    if (pkcs8_pem_len == 0 or pkcs8_pem_ptr == null) return -1;
    if (msg_len > 0 and msg_ptr == null) return -1;

    const pem = pkcs8_pem_ptr.?[0..pkcs8_pem_len];
    const msg = if (msg_ptr) |p| p[0..msg_len] else "";

    var der_scratch: [4096]u8 = undefined;
    const key = parsePkcs8Pem(pem, &der_scratch) catch return -1;

    var em: [256]u8 = undefined;
    buildEmSha256(msg, &em);

    const m = M2048.fromBytes(key.n, .big) catch return -1;
    const em_fe = M2048.Fe.fromBytes(m, &em, .big) catch return -1;
    // Secret exponent → constant-time path.
    const sig_fe = m.powWithEncodedExponent(em_fe, key.d, .big) catch return -1;
    sig_fe.toBytes(sig_out.?[0..256], .big) catch return -1;

    return 256;
}

/// RSASSA-PKCS1-v1_5 verify with SHA-256, RSA-2048.
///
/// Public key is provided as raw (n, e) bytes — extracted from a JWKS,
/// SPKI key, or upstream key discovery. The verifier deliberately does
/// not parse PEM: callers carrying around a PKCS#8 private key on the
/// verify path is an anti-pattern.
///
/// Returns:
///    1  signature matches
///    0  mismatch — also wrong sig/n length, null pointers, math failure
export fn hpm_crypto_rs256_verify(
    n_ptr: ?[*]const u8,
    n_len: usize,
    e_ptr: ?[*]const u8,
    e_len: usize,
    msg_ptr: ?[*]const u8,
    msg_len: usize,
    sig_ptr: ?[*]const u8,
    sig_len: usize,
) c_int {
    if (sig_len != 256 or n_len != 256) return 0;
    if (n_ptr == null or e_ptr == null or sig_ptr == null) return 0;
    if (e_len == 0) return 0;
    if (msg_len > 0 and msg_ptr == null) return 0;

    const n = n_ptr.?[0..n_len];
    const e = e_ptr.?[0..e_len];
    const sig = sig_ptr.?[0..sig_len];
    const msg = if (msg_ptr) |p| p[0..msg_len] else "";

    const m = M2048.fromBytes(n, .big) catch return 0;
    const sig_fe = M2048.Fe.fromBytes(m, sig, .big) catch return 0;
    // Public exponent → fast path (not constant-time, but e is public).
    const em_fe = m.powWithEncodedPublicExponent(sig_fe, e, .big) catch return 0;
    var em_recovered: [256]u8 = undefined;
    em_fe.toBytes(&em_recovered, .big) catch return 0;

    var em_expected: [256]u8 = undefined;
    buildEmSha256(msg, &em_expected);

    return if (timingSafeEql([256]u8, em_recovered, em_expected)) 1 else 0;
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

// ---------------------------------------------------------------------------
// RS256 tests
//
// Fixture: real RSA-2048 PKCS#8 PEM generated with OpenSSL for test use
// only. NOT a production key; do not reuse anywhere. Kept in sync with
// `ffi/zig/tests/fixtures/test_rsa2048.pem` (loaded as a file by CI for
// differential testing). Inlined here because Zig 0.15 restricts
// @embedFile to paths inside the module's source root.
// ---------------------------------------------------------------------------

const test_pkcs8_pem =
    \\-----BEGIN PRIVATE KEY-----
    \\MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDaceAaxn4HNMf7
    \\7SptqIOlvR8L5V+wFJoo4YnjISGmpPtQGsGpDUA+X8TCyDw+e0GVaUcM70Ca3eYh
    \\5KBsEx75oHa9NE17xqInMx8lKgEhRNkVbhPfXyb/SE9/TMEaDmCcum6DUSxe18Jp
    \\YHDeQkOuDoL3I+Ox6+fwPLg3cSwn6jx3CSVvgq7P9xJGqrgm9ZyMGIUGz6erpxzx
    \\jBdiXTQPF8X3BTcpvTyzkl3byRDvYju9ELPmNtzeeLyDlOiC0uqrLytuAMJe1Zs4
    \\U/u3b+W1cNLXKF5HMdFtibKuhKUMPPKUKJ8Hl9jhhLNXOkXog6j5SDTpI8csrVKX
    \\bZBb0sXHAgMBAAECggEANTXf/SW0tVSqEjfnSebuioTS9zbcZCvgkWy/BdCgPdOa
    \\VBzwZ5mOuKLjbv8PjbjAdQC8Ce6NsiuzTzY9zZWqyevIgLYo2am8/gd54rekptH6
    \\fzndJWAsQ6r9kmjD8PDnn8XZ/arcQA4WkUyosbs6eT+Xr1PStxhb2y0vQnIS63Wz
    \\/pZ9vcjbSY4nTU+lPvN5jSbC82vjiUSGWPnAz4hQw5n9ZoZ41N45H/UjQI1t5Esd
    \\0KKIOiq2Sl2ySAk+XOGm5OiehEtiATyfrHsEXcJP9weHYreYqwYoD1HMClN/v9nv
    \\r50zsWzFoetWf1CvV37Tdg2TapSC1HrOHzolR4ZgwQKBgQD5SIaerrihYT9rszZd
    \\Nhf6wSXVLCH3TgBJbZoh6na0u2W/A04vgipaA1MS3nIt6ld4vqpw+IDSVVkdnDq3
    \\dtmSaU69txVP8x+ihyMIjGv+0L7iWgjvG5c5Ear6GKMmsimbkfaNrErrzRlSkotO
    \\CxoZ4KdWbWpAUJU+ndgglpYT2QKBgQDgVKLJI1ZiEHddRIJ9eRjD1+ZvCI9t9TlG
    \\HgSpDUZClWYxR2zjriGz9NhrCN/cIO28EfU5rjmocRHRvg0NOFyUYjaVZ7wzKhz4
    \\/sM/30gwH+iNOLJ2gUFilQ6VPW7mBP4+apu5gD17gEttbSO7gI+MlJpNg75xe9nx
    \\0Uv7tOLCnwKBgHPjLoooibakYfpslvJgSmeNUUw3txakEWgRZt0rhcHheJyDKd7W
    \\MWAlOYKFHSmRTtbYNJ5OOH0Ppl0omvddbiotgKibq3G+gc9p6XR461/LpWHPH2Yh
    \\On0SZJzdxUMhAkzLX4ZfOXlDoOkNLWu7p4euM7zvIr0BeVBhyu7jcqOJAoGAbGl6
    \\oinpvUqn5PMO/QRg64STYGWKq2EvZKttJSW9JsB8uqQCA6ZLs2RIkrGfPgrL2W/0
    \\SwPf6X97VRm7xP/P/gXYyytu0GsxxUOZqGyHvnotMNKNrKeaqcHPYmBmD9Op6xAq
    \\YeOP0veVfDSaaCshNJc8WumoR7/K/Aph5irsy5ECgYBSz/v3k6/Pue1WNCxNpoI7
    \\h5OzCkhDa+dWk9Rr3MHh9yKZ20qWe6xzkeLN91sCTWG5L3dqBPCCarAq8l92/zVc
    \\dbsD0DtQQ9xUmmaxqY7JlIDPETAUG9vTq3okQQ4kGAWedAowUTxFYPvADN0SXc3X
    \\H/0wHLAIg1X4/wImKYi45Q==
    \\-----END PRIVATE KEY-----
;

// KAT: `echo -n "hello world" | openssl dgst -sha256 -sign test_rsa2048.pem`
// Generated 2026-05-28 against the fixture above. Any change to the
// fixture invalidates this vector — regenerate both together.
const kat_msg = "hello world";
const kat_sig = [_]u8{
    0x9e, 0xfd, 0xdf, 0x25, 0x69, 0x01, 0x93, 0xd6, 0x34, 0xaa, 0x58, 0x5f,
    0xb8, 0x37, 0xe6, 0x8f, 0x63, 0x73, 0xdc, 0xed, 0x9e, 0x64, 0xfb, 0xd8,
    0x09, 0x43, 0x35, 0x2e, 0xf4, 0x86, 0xc7, 0x8a, 0x5f, 0x17, 0xc3, 0x6c,
    0x22, 0x62, 0xe8, 0x0e, 0x18, 0x15, 0xfa, 0x8d, 0xc6, 0x74, 0x2d, 0x42,
    0xac, 0xa3, 0xd0, 0x61, 0xaf, 0x32, 0xc1, 0x60, 0x53, 0xf7, 0x2f, 0xd3,
    0xbb, 0xae, 0xfa, 0x92, 0xb5, 0x91, 0xfe, 0x1c, 0x2b, 0x70, 0xc7, 0xbb,
    0xa1, 0x41, 0xb9, 0xf2, 0xc1, 0x87, 0xbe, 0x3d, 0xd2, 0x98, 0xa3, 0x1c,
    0x0c, 0x37, 0xb7, 0x29, 0xe9, 0x43, 0x35, 0xf7, 0x8b, 0x88, 0x7f, 0xdb,
    0x42, 0xd3, 0x1b, 0x93, 0x2f, 0xca, 0x10, 0x15, 0xfa, 0x33, 0xc9, 0xfb,
    0x84, 0xc0, 0x46, 0x1b, 0x62, 0xb5, 0x49, 0x3b, 0xb3, 0xb0, 0x82, 0x1c,
    0x48, 0xa2, 0x7f, 0x38, 0xa2, 0x55, 0x9c, 0xbf, 0xaf, 0x51, 0x41, 0xa4,
    0x55, 0xd8, 0xec, 0xff, 0x5c, 0x60, 0x67, 0xbb, 0xf6, 0x69, 0x5d, 0x2e,
    0x79, 0x6a, 0x6b, 0xe7, 0x68, 0xdc, 0x55, 0x68, 0xe6, 0x9e, 0x35, 0xfa,
    0x12, 0x9b, 0x04, 0xeb, 0xdb, 0xa2, 0xfc, 0x2d, 0x67, 0x3a, 0xc2, 0x9f,
    0x4f, 0xc8, 0x23, 0x81, 0x94, 0xac, 0xf6, 0x36, 0x36, 0x79, 0x7d, 0x76,
    0x5f, 0x7e, 0x9d, 0x65, 0xd1, 0xa6, 0xeb, 0x2b, 0x67, 0x51, 0xbf, 0x3f,
    0xfb, 0x5c, 0xd2, 0x0a, 0x18, 0x8d, 0x9e, 0x59, 0xd1, 0x36, 0xfe, 0x8c,
    0xe6, 0xc3, 0xb0, 0x8f, 0x05, 0x99, 0x3b, 0xe4, 0x59, 0xf9, 0xa3, 0x0e,
    0xe0, 0x48, 0x1e, 0xd5, 0xd4, 0xbb, 0x8c, 0x9d, 0x5c, 0xa9, 0xfc, 0xb0,
    0x0f, 0xa2, 0xda, 0x5e, 0xaf, 0x22, 0xe4, 0x5e, 0xc1, 0xb9, 0xeb, 0x69,
    0xf5, 0x62, 0x9d, 0x70, 0x68, 0x4f, 0x6e, 0xc3, 0xa9, 0x13, 0x2f, 0xe8,
    0xd0, 0x22, 0x48, 0xfe,
};

test "rs256: KAT against OpenSSL signature" {
    var sig: [256]u8 = undefined;
    const rc = hpm_crypto_rs256_sign(
        test_pkcs8_pem.ptr,
        test_pkcs8_pem.len,
        kat_msg.ptr,
        kat_msg.len,
        &sig,
        sig.len,
    );
    try testing.expectEqual(@as(isize, 256), rc);
    try testing.expectEqualSlices(u8, &kat_sig, &sig);
}

test "rs256: deterministic (same input → same output)" {
    var sig1: [256]u8 = undefined;
    var sig2: [256]u8 = undefined;
    _ = hpm_crypto_rs256_sign(test_pkcs8_pem.ptr, test_pkcs8_pem.len, kat_msg.ptr, kat_msg.len, &sig1, sig1.len);
    _ = hpm_crypto_rs256_sign(test_pkcs8_pem.ptr, test_pkcs8_pem.len, kat_msg.ptr, kat_msg.len, &sig2, sig2.len);
    try testing.expectEqualSlices(u8, &sig1, &sig2);
}

test "rs256: size query returns 256" {
    const rc = hpm_crypto_rs256_sign(
        test_pkcs8_pem.ptr,
        test_pkcs8_pem.len,
        kat_msg.ptr,
        kat_msg.len,
        null,
        0,
    );
    try testing.expectEqual(@as(isize, 256), rc);
}

test "rs256: empty PEM returns -1" {
    var sig: [256]u8 = undefined;
    const rc = hpm_crypto_rs256_sign(null, 0, kat_msg.ptr, kat_msg.len, &sig, sig.len);
    try testing.expectEqual(@as(isize, -1), rc);
}

test "rs256: malformed PEM (missing header) returns -1" {
    var sig: [256]u8 = undefined;
    const garbage = "this is not a PEM at all";
    const rc = hpm_crypto_rs256_sign(garbage.ptr, garbage.len, kat_msg.ptr, kat_msg.len, &sig, sig.len);
    try testing.expectEqual(@as(isize, -1), rc);
}

test "rs256: round-trip sign + verify" {
    // Sign with the private key, recover (n, e) from the same PEM, then
    // run our verify path. Proves the math is internally consistent.
    var sig: [256]u8 = undefined;
    const sign_rc = hpm_crypto_rs256_sign(
        test_pkcs8_pem.ptr,
        test_pkcs8_pem.len,
        kat_msg.ptr,
        kat_msg.len,
        &sig,
        sig.len,
    );
    try testing.expectEqual(@as(isize, 256), sign_rc);

    var scratch: [4096]u8 = undefined;
    const parsed = try parsePkcs8Pem(test_pkcs8_pem, &scratch);
    const verify_rc = hpm_crypto_rs256_verify(
        parsed.n.ptr,
        parsed.n.len,
        parsed.e.ptr,
        parsed.e.len,
        kat_msg.ptr,
        kat_msg.len,
        &sig,
        sig.len,
    );
    try testing.expectEqual(@as(c_int, 1), verify_rc);
}

test "rs256: verify rejects altered message" {
    var scratch: [4096]u8 = undefined;
    const parsed = try parsePkcs8Pem(test_pkcs8_pem, &scratch);
    const wrong_msg = "Hello world"; // capital H
    const verify_rc = hpm_crypto_rs256_verify(
        parsed.n.ptr,
        parsed.n.len,
        parsed.e.ptr,
        parsed.e.len,
        wrong_msg.ptr,
        wrong_msg.len,
        &kat_sig,
        kat_sig.len,
    );
    try testing.expectEqual(@as(c_int, 0), verify_rc);
}

test "rs256: verify rejects wrong-length signature" {
    var scratch: [4096]u8 = undefined;
    const parsed = try parsePkcs8Pem(test_pkcs8_pem, &scratch);
    const short_sig = [_]u8{0} ** 128;
    const verify_rc = hpm_crypto_rs256_verify(
        parsed.n.ptr,
        parsed.n.len,
        parsed.e.ptr,
        parsed.e.len,
        kat_msg.ptr,
        kat_msg.len,
        &short_sig,
        short_sig.len,
    );
    try testing.expectEqual(@as(c_int, 0), verify_rc);
}
