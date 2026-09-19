#!/usr/bin/env python3
"""Nano key derivation in pure Python: ed25519 over blake2b, no node, no dependencies.

nanoswarm's whole premise is that a runtime should be light, so adding node and nanocurrency to it
just to make one address would be the wrong trade. Moving a seed from a box that already has those
tools would be worse: a seed that has been on two machines is a seed on two machines for ever.

Nano is ed25519 with blake2b-512 in place of sha512, which is the only difference from the reference
implementation. Verified against a published test vector AND against a live account before use.
"""
import hashlib

P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
I = pow(2, (P - 1) // 4, P)
ALPHABET = "13456789abcdefghijkmnopqrstuwxyz"


def _inv(x):
    return pow(x, P - 2, P)


def _recover_x(y):
    xx = (y * y - 1) * _inv(D * y * y + 1)
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = (x * I) % P
    if x % 2 != 0:
        x = P - x
    return x


BY = (4 * _inv(5)) % P
BX = _recover_x(BY)
B = (BX % P, BY % P, 1, (BX * BY) % P)


def _add(p, q):
    """Extended-coordinate addition (X, Y, Z, T), add-2008-hwcd-3.

    The intermediates E, F, G, H are NOT the result: returning them directly gives a point that
    compresses to a plausible-looking but wrong public key, which is exactly how this was caught -
    the derived secret key matched nanocurrency's byte for byte while the address did not.
    """
    a = ((p[1] - p[0]) * (q[1] - q[0])) % P
    b = ((p[1] + p[0]) * (q[1] + q[0])) % P
    c = (2 * p[3] * q[3] * D) % P
    d = (2 * p[2] * q[2]) % P
    e, f, g, h = (b - a) % P, (d - c) % P, (d + c) % P, (b + a) % P
    return ((e * f) % P, (g * h) % P, (f * g) % P, (e * h) % P)


def _mul(p, e):
    q = (0, 1, 1, 0)
    while e > 0:
        if e & 1:
            q = _add(q, p)
        p = _add(p, p)
        e >>= 1
    return q


def _compress(p):
    zi = _inv(p[2])
    x = (p[0] * zi) % P
    y = (p[1] * zi) % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def private_key(seed: bytes, index: int = 0) -> bytes:
    """blake2b(seed || big-endian index) -> the account's private key."""
    return hashlib.blake2b(seed + index.to_bytes(4, "big"), digest_size=32).digest()


def public_key(priv: bytes) -> bytes:
    h = hashlib.blake2b(priv, digest_size=64).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8          # clamp low 3 bits
    a |= 1 << 254                # and set the high bit
    return _compress(_mul(B, a))


def _b32(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    bits = len(data) * 8
    out = []
    for shift in range(bits - 5, -5, -5):
        out.append(ALPHABET[(n >> shift) & 31] if shift >= 0 else ALPHABET[(n << -shift) & 31])
    return "".join(out)


def address(pub: bytes, prefix: str = "nano_") -> str:
    # 260 bits: four zero bits of padding, then the 256-bit key, so it lands on a 5-bit boundary.
    body = _b32(b"\x00\x00\x00" + pub)[4:]
    checksum = hashlib.blake2b(pub, digest_size=5).digest()[::-1]
    return prefix + body + _b32(checksum)


def account_from_seed(seed_hex: str, index: int = 0) -> str:
    return address(public_key(private_key(bytes.fromhex(seed_hex), index)))


if __name__ == "__main__":
    # The all-zero seed at index 0. This constant was CHECKED, not remembered: the first value written
    # here was wrong and would have passed nothing. The algorithm was validated by deriving a live
    # account (Unstuck's, on Unstuck's own box) and matching it character for character against the
    # address nanocurrency produced; this vector was then recorded from the validated implementation.
    got = account_from_seed("0" * 64, 0)
    want = "nano_3i1aq1cchnmbn9x5rsbap8b15akfh7wj7pwskuzi7ahz8oq6cobd99d4r3b7"
    print("vector:", "PASS" if got == want else f"FAIL got {got}")


# ---------------------------------------------------------------- blocks and signatures
#
# Signing is ed25519 with blake2b-512 in place of sha512, the same single substitution as key
# derivation. Validated against nanocurrency before it was ever used on a real block: a signer that
# is merely self-consistent will verify its own wrong signatures happily.

STATE_PREAMBLE = (6).to_bytes(32, "big")


def account_to_pub(addr: str) -> bytes:
    """The public key inside an address, with the checksum checked. xrb_ and nano_ both accepted."""
    body = addr.split("_", 1)[1]
    key_part, check_part = body[:52], body[52:]
    n = 0
    for ch in key_part:
        n = (n << 5) | ALPHABET.index(ch)
    pub = n.to_bytes(35, "big")[3:]        # drop the four bits of padding
    c = 0
    for ch in check_part:
        c = (c << 5) | ALPHABET.index(ch)
    if c.to_bytes(5, "big") != hashlib.blake2b(pub, digest_size=5).digest()[::-1]:
        raise ValueError("bad address checksum")
    return pub


def state_hash(account_pub: bytes, previous: bytes, rep_pub: bytes, balance_raw: int, link: bytes) -> bytes:
    """The hash a state block is signed over. Field order is part of the protocol; do not reorder."""
    h = hashlib.blake2b(digest_size=32)
    for part in (STATE_PREAMBLE, account_pub, previous, rep_pub,
                 int(balance_raw).to_bytes(16, "big"), link):
        h.update(part)
    return h.digest()


def sign(message: bytes, priv: bytes) -> bytes:
    h = hashlib.blake2b(priv, digest_size=64).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    A = _compress(_mul(B, a))
    r = int.from_bytes(hashlib.blake2b(h[32:] + message, digest_size=64).digest(), "little") % L
    R = _compress(_mul(B, r))
    k = int.from_bytes(hashlib.blake2b(R + A + message, digest_size=64).digest(), "little") % L
    S = (r + k * a) % L
    return R + S.to_bytes(32, "little")
