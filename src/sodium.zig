// This is a shim between libsodium's interface and std.crypto,
// exporting only the subset of symbols that netcode.io needs.

const std = @import("std");
const Csprng = std.rand.DefaultCsprng;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const XChaCha20Poly1305 = std.crypto.aead.chacha_poly.XChaCha20Poly1305;

const SUCCESS: c_int = 0;
const FAILURE: c_int = -1;
const ALREADY_INITIALIZED: c_int = 1;

var csprng: Csprng = undefined;
var random: ?std.rand.Random = null;

export fn sodium_init() c_int {
    if (random) |_| return ALREADY_INITIALIZED;
    var secret_seed = [_]u8{0} ** Csprng.secret_seed_length;
    std.os.getrandom(&secret_seed) catch return FAILURE;
    csprng = Csprng.init(secret_seed);
    random = csprng.random();
    return SUCCESS;
}

export fn randombytes_buf(buf: [*c]u8, size: usize) c_int {
    if (random) |r| {
        r.bytes(buf[0..size]);
        return SUCCESS;
    } else {
        return FAILURE;
    }
}

export fn crypto_aead_chacha20poly1305_ietf_encrypt(c: [*c]u8, clen_p: [*c]c_longlong, m: [*c]const u8, mlen: c_longlong, ad: [*c]const u8, adlen: c_longlong, nsec: [*c]const u8, npub: [*c]const u8, k: [*c]const u8) c_int {
    return encrypt(ChaCha20Poly1305, c, clen_p, m, mlen, ad, adlen, nsec, npub, k);
}

export fn crypto_aead_chacha20poly1305_ietf_decrypt(m: [*c]u8, mlen_p: [*c]c_longlong, nsec: [*c]u8, c: [*c]const u8, clen: c_longlong, ad: [*c]const u8, adlen: c_longlong, npub: [*c]const u8, k: [*c]const u8) c_int {
    return decrypt(ChaCha20Poly1305, m, mlen_p, nsec, c, clen, ad, adlen, npub, k);
}

export fn crypto_aead_xchacha20poly1305_ietf_encrypt(c: [*c]u8, clen_p: [*c]c_longlong, m: [*c]const u8, mlen: c_longlong, ad: [*c]const u8, adlen: c_longlong, nsec: [*c]const u8, npub: [*c]const u8, k: [*c]const u8) c_int {
    return encrypt(XChaCha20Poly1305, c, clen_p, m, mlen, ad, adlen, nsec, npub, k);
}

export fn crypto_aead_xchacha20poly1305_ietf_decrypt(m: [*c]u8, mlen_p: [*c]c_longlong, nsec: [*c]u8, c: [*c]const u8, clen: c_longlong, ad: [*c]const u8, adlen: c_longlong, npub: [*c]const u8, k: [*c]const u8) c_int {
    return decrypt(XChaCha20Poly1305, m, mlen_p, nsec, c, clen, ad, adlen, npub, k);
}

fn encrypt(
    comptime Aead: type,
    c: [*c]u8,
    clen_p: [*c]c_longlong,
    m: [*c]const u8,
    mlen: c_longlong,
    ad: [*c]const u8,
    adlen: c_longlong,
    nsec: [*c]const u8,
    npub: [*c]const u8,
    k: [*c]const u8,
) c_int {
    _ = nsec;
    const m_length = @intCast(usize, mlen);
    const c_length = m_length + Aead.tag_length;
    var tag = c + m_length;
    clen_p.* = @intCast(c_longlong, c_length);
    Aead.encrypt(
        c[0..m_length],
        tag[0..Aead.tag_length],
        m[0..m_length],
        if (ad == null) &[0]u8{} else ad[0..@intCast(usize, adlen)],
        npub[0..Aead.nonce_length].*,
        k[0..Aead.key_length].*,
    );
    return SUCCESS;
}

fn decrypt(
    comptime Aead: type,
    m: [*c]u8,
    mlen_p: [*c]c_longlong,
    nsec: [*c]u8,
    c: [*c]const u8,
    clen: c_longlong,
    ad: [*c]const u8,
    adlen: c_longlong,
    npub: [*c]const u8,
    k: [*c]const u8,
) c_int {
    _ = nsec;
    const c_length = @intCast(usize, clen);
    const m_length = c_length - Aead.tag_length;
    const tag = c + m_length;
    if (mlen_p != null) {
        mlen_p.* = @intCast(c_longlong, m_length);
    }
    Aead.decrypt(
        m[0..m_length],
        c[0..m_length],
        tag[0..Aead.tag_length].*,
        if (ad == null) &[0]u8{} else ad[0..@intCast(usize, adlen)],
        npub[0..Aead.nonce_length].*,
        k[0..Aead.key_length].*,
    ) catch {
        return FAILURE;
    };
    return SUCCESS;
}

// =====================================================================================================================
// TESTING

const m0 = "testing libsodium-to-std.crypto shim!";
const buffer_len = 500;
const ad_len = 100;

test "message round-trips via ChaCha20Poly1305" {
    var c: [buffer_len]u8 = undefined;
    var clen: c_longlong = undefined;
    var ad: [ad_len]u8 = undefined;
    var npub: [ChaCha20Poly1305.nonce_length]u8 = undefined;
    var k: [ChaCha20Poly1305.key_length]u8 = undefined;
    var m1: [buffer_len]u8 = undefined;
    var m1len: c_longlong = undefined;

    if (sodium_init() == FAILURE) unreachable;
    if (randombytes_buf(&ad, ad_len) == FAILURE) unreachable;
    if (randombytes_buf(&npub, XChaCha20Poly1305.nonce_length) == FAILURE) unreachable;
    if (randombytes_buf(&k, XChaCha20Poly1305.key_length) == FAILURE) unreachable;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(&c, &clen, m0, m0.len, &ad, ad_len, null, &npub, &k) == FAILURE) unreachable;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(&m1, &m1len, null, &c, clen, &ad, ad_len, &npub, &k) == FAILURE) unreachable;

    try std.testing.expectEqualStrings(m0, m1[0..@intCast(usize, m1len)]);
}

test "message round-trips via XChaCha20Poly1305" {
    var c: [buffer_len]u8 = undefined;
    var clen: c_longlong = undefined;
    var ad: [ad_len]u8 = undefined;
    var npub: [XChaCha20Poly1305.nonce_length]u8 = undefined;
    var k: [XChaCha20Poly1305.key_length]u8 = undefined;
    var m1: [buffer_len]u8 = undefined;
    var m1len: c_longlong = undefined;

    if (sodium_init() == FAILURE) unreachable;
    if (randombytes_buf(&ad, ad_len) == FAILURE) unreachable;
    if (randombytes_buf(&npub, XChaCha20Poly1305.nonce_length) == FAILURE) unreachable;
    if (randombytes_buf(&k, XChaCha20Poly1305.key_length) == FAILURE) unreachable;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(&c, &clen, m0, m0.len, &ad, ad_len, null, &npub, &k) == FAILURE) unreachable;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(&m1, &m1len, null, &c, clen, &ad, ad_len, &npub, &k) == FAILURE) unreachable;

    try std.testing.expectEqualStrings(m0, m1[0..@intCast(usize, m1len)]);
}
