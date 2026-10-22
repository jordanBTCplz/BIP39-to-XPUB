#!/usr/bin/env python3
"""
Offline: BIP39 words (12/15/18/21/24) -> account xpub, descriptors, first address,
optional --xprv.  Mainnet, single-sig only.

Stdlib only. No pip. No network.

Put the official english.txt next to this file:
  https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt
  sha256 2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda
The script verifies this hash and refuses to run on any other file.

Supported account paths (exactly 3 hardened levels, coin type 0h):
  m/84h/0h/0h  native SegWit (bc1q...)   wpkh(...)      default
  m/49h/0h/0h  nested SegWit (3...)      sh(wpkh(...))
  m/44h/0h/0h  legacy (1...)             pkh(...)

Self-test (run before using a real seed):
  python3 seed_to_xpub_fixed.py --test
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import hmac
import sys
import unicodedata
from pathlib import Path

WORDLIST_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"

# secp256k1
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (Gx, Gy)

HARD = 0x80000000
XPUB_VER = bytes.fromhex("0488B21E")
XPRV_VER = bytes.fromhex("0488ADE4")


# ---------------------------------------------------------------- BIP39

def load_wordlist(path: Path) -> list[str]:
    try:
        raw = path.read_bytes()
    except OSError as e:
        sys.exit(f"cannot read wordlist: {e}")
    if hashlib.sha256(raw).hexdigest() != WORDLIST_SHA256:
        sys.exit(f"{path}: sha256 is not the official BIP39 English wordlist ({WORDLIST_SHA256})")
    words = [ln.strip() for ln in raw.decode("utf-8").splitlines() if ln.strip()]
    if len(words) != 2048:
        sys.exit(f"{path} must have 2048 words, found {len(words)}")
    return words


def nfkd(s: str) -> str:
    return unicodedata.normalize("NFKD", s)


def mnemonic_to_entropy(words: list[str], wordlist: list[str]) -> bytes:
    ms = len(words)
    if ms not in (12, 15, 18, 21, 24):
        sys.exit("need 12/15/18/21/24 words")
    idx = {w: i for i, w in enumerate(wordlist)}
    n = 0
    for w in words:
        if w not in idx:
            sys.exit(f"not on the wordlist: {w}")
        n = (n << 11) | idx[w]
    ent_bits = ms * 32 // 3
    cs_bits = ent_bits // 32
    want = n & ((1 << cs_bits) - 1)
    entropy = (n >> cs_bits).to_bytes(ent_bits // 8, "big")
    got = hashlib.sha256(entropy).digest()[0] >> (8 - cs_bits)
    if got != want:
        sys.exit("checksum failed: words are not a valid BIP39 mnemonic")
    return entropy


def entropy_to_mnemonic(entropy: bytes, wordlist: list[str]) -> list[str]:
    """Self-test helper only."""
    ent_bits = len(entropy) * 8
    cs_bits = ent_bits // 32
    cs = hashlib.sha256(entropy).digest()[0] >> (8 - cs_bits)
    n = (int.from_bytes(entropy, "big") << cs_bits) | cs
    total = ent_bits + cs_bits
    return [wordlist[(n >> (total - 11 * (i + 1))) & 0x7FF] for i in range(total // 11)]


def mnemonic_to_seed(words: list[str], passphrase: str) -> bytes:
    pw = nfkd(" ".join(words)).encode("utf-8")
    salt = nfkd("mnemonic" + passphrase).encode("utf-8")
    return hashlib.pbkdf2_hmac("sha512", pw, salt, 2048, dklen=64)


# ---------------------------------------------------------------- EC math

def _inv(a: int, m: int) -> int:
    return pow(a, m - 2, m)


def _add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1) * _inv(2 * y1, P) % P
    else:
        lam = (y2 - y1) * _inv((x2 - x1) % P, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def _mul(k: int, pt=G):
    if k % N == 0 or pt is None:
        return None
    k = k % N
    out = None
    acc = pt
    while k:
        if k & 1:
            out = _add(out, acc)
        acc = _add(acc, acc)
        k >>= 1
    return out


def ser_p(pt) -> bytes:
    x, y = pt
    return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")


# ---------------------------------------------------------------- hashes

def hash160(b: bytes) -> bytes:
    sha = hashlib.sha256(b).digest()
    try:
        return hashlib.new("ripemd160", sha).digest()
    except ValueError:
        return _ripemd160(sha)


def _ripemd160(data: bytes) -> bytes:
    def rol(x, n):
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    kl = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
        3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
        1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
        4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
    ]
    kr = [
        5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
        6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
        15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
        8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
        12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
    ]
    sl = [
        11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
        7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
        11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
        11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
        9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
    ]
    sr = [
        8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
        9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
        9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
        15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
        8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
    ]
    fl = [
        lambda x, y, z: x ^ y ^ z,
        lambda x, y, z: (x & y) | (~x & z),
        lambda x, y, z: (x | ~y) ^ z,
        lambda x, y, z: (x & z) | (y & ~z),
        lambda x, y, z: x ^ (y | ~z),
    ]
    ml = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
    mr = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]
    ml_data = data + b"\x80" + b"\x00" * ((55 - len(data)) % 64) + (len(data) * 8).to_bytes(8, "little")
    h0, h1, h2, h3, h4 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
    for i in range(0, len(ml_data), 64):
        x = [int.from_bytes(ml_data[i + 4 * j : i + 4 * j + 4], "little") for j in range(16)]
        al = ar = h0
        bl = br = h1
        cl = cr = h2
        dl = dr = h3
        el = er = h4
        for j in range(80):
            t = (rol((al + fl[j // 16](bl, cl, dl) + x[kl[j]] + ml[j // 16]) & 0xFFFFFFFF, sl[j]) + el) & 0xFFFFFFFF
            al, el, dl, cl, bl = el, dl, rol(cl, 10), bl, t
            t = (rol((ar + fl[4 - j // 16](br, cr, dr) + x[kr[j]] + mr[j // 16]) & 0xFFFFFFFF, sr[j]) + er) & 0xFFFFFFFF
            ar, er, dr, cr, br = er, dr, rol(cr, 10), br, t
        t = (h1 + cl + dr) & 0xFFFFFFFF
        h1 = (h2 + dl + er) & 0xFFFFFFFF
        h2 = (h3 + el + ar) & 0xFFFFFFFF
        h3 = (h4 + al + br) & 0xFFFFFFFF
        h4 = (h0 + bl + cr) & 0xFFFFFFFF
        h0 = t
    return b"".join(int(v).to_bytes(4, "little") for v in (h0, h1, h2, h3, h4))


# ---------------------------------------------------------------- encodings

B58 = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58check(payload: bytes) -> str:
    chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    raw = payload + chk
    n = int.from_bytes(raw, "big")
    out = b""
    while n:
        n, r = divmod(n, 58)
        out = bytes([B58[r]]) + out
    pad = 0
    for b in raw:
        if b == 0:
            pad += 1
        else:
            break
    return (B58[0:1] * pad + out).decode()


def bech32_encode(hrp: str, witver: int, witprog: bytes) -> str:
    """Witness v0 only (bech32, not bech32m)."""
    charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

    def convertbits(data, frombits, tobits, pad=True):
        acc = 0
        bits = 0
        ret = []
        maxv = (1 << tobits) - 1
        for v in data:
            acc = (acc << frombits) | v
            bits += frombits
            while bits >= tobits:
                bits -= tobits
                ret.append((acc >> bits) & maxv)
        if pad and bits:
            ret.append((acc << (tobits - bits)) & maxv)
        return ret

    def polymod(values):
        gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
        chk = 1
        for v in values:
            b = chk >> 25
            chk = ((chk & 0x1FFFFFF) << 5) ^ v
            for i in range(5):
                if (b >> i) & 1:
                    chk ^= gen[i]
        return chk

    def hrp_expand(h):
        return [ord(x) >> 5 for x in h] + [0] + [ord(x) & 31 for x in h]

    if witver != 0:
        raise ValueError("only witness v0 supported")
    data = [witver] + convertbits(list(witprog), 8, 5)
    values = hrp_expand(hrp) + data
    p = polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    combined = data + [(p >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(charset[d] for d in combined)


# Output descriptor checksum (BIP380), so printed descriptors import directly.
_DESC_IN = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "
_DESC_OUT = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_DESC_GEN = [0xF5DEE51989, 0xA9FDCA3312, 0x1BAB10E32D, 0x3706B1677A, 0x644D626FFD]


def desc_checksum(desc: str) -> str:
    chk = 1
    groups = []

    def feed(v):
        nonlocal chk
        top = chk >> 35
        chk = ((chk & 0x7FFFFFFFF) << 5) ^ v
        for i in range(5):
            if (top >> i) & 1:
                chk ^= _DESC_GEN[i]

    for ch in desc:
        v = _DESC_IN.find(ch)
        if v < 0:
            sys.exit(f"bad character in descriptor: {ch!r}")
        feed(v & 31)
        groups.append(v >> 5)
        if len(groups) == 3:
            feed(groups[0] * 9 + groups[1] * 3 + groups[2])
            groups = []
    if len(groups) == 1:
        feed(groups[0])
    elif len(groups) == 2:
        feed(groups[0] * 3 + groups[1])
    for _ in range(8):
        feed(0)
    chk ^= 1
    return desc + "#" + "".join(_DESC_OUT[(chk >> (5 * (7 - i))) & 31] for i in range(8))


# ---------------------------------------------------------------- BIP32

def master_from_seed(seed: bytes):
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    k = int.from_bytes(I[:32], "big")
    if k == 0 or k >= N:
        sys.exit("invalid master key (astronomically unlikely); try a different passphrase")
    return k, I[32:]


def ckd_priv(k: int, chain: bytes, index: int):
    if index >= HARD:
        data = b"\x00" + k.to_bytes(32, "big") + index.to_bytes(4, "big")
    else:
        data = ser_p(_mul(k)) + index.to_bytes(4, "big")
    I = hmac.new(chain, data, hashlib.sha512).digest()
    il = int.from_bytes(I[:32], "big")
    ki = (il + k) % N
    if il >= N or ki == 0:
        sys.exit(f"invalid child key at index {index} (astronomically unlikely)")
    return ki, I[32:]


def encode_ext(ver: bytes, depth: int, fpr: bytes, child: int, chain: bytes, key: bytes) -> str:
    return b58check(ver + bytes([depth]) + fpr + child.to_bytes(4, "big") + chain + key)


def fingerprint(k: int) -> bytes:
    return hash160(ser_p(_mul(k)))[:4]


def parse_path(s: str) -> list[int]:
    s = s.strip()
    if s[:1] in ("m", "M"):
        s = s[1:]
    s = s.lstrip("/")
    if not s:
        return []
    out = []
    for p in s.split("/"):
        hardened = p[-1:] in ("h", "H", "'")
        try:
            n = int(p[:-1] if hardened else p)
        except ValueError:
            sys.exit(f"bad path element: {p!r}")
        if not 0 <= n < HARD:
            sys.exit(f"path index out of range: {p!r}")
        out.append(n + HARD if hardened else n)
    return out


def fmt_path(path: list[int]) -> str:
    return "/".join(f"{i - HARD}h" if i >= HARD else str(i) for i in path)


def validate_path(path: list[int]) -> str:
    """Return the script type for a supported path, or exit."""
    if len(path) != 3 or any(i < HARD for i in path):
        sys.exit("path must be exactly 3 hardened levels, e.g. m/84h/0h/0h")
    purpose, coin = path[0] - HARD, path[1] - HARD
    kinds = {84: "p2wpkh", 49: "p2sh-p2wpkh", 44: "p2pkh"}
    if purpose not in kinds:
        sys.exit(f"unsupported purpose {purpose}h (supported: 84h, 49h, 44h)")
    if coin != 0:
        sys.exit(f"coin type {coin}h not supported: this script is mainnet only (0h)")
    return kinds[purpose]


def derive_account(seed: bytes, path: list[int]):
    k, c = master_from_seed(seed)
    xfp = fingerprint(k)
    parent_fpr = b"\x00" * 4
    depth = 0
    child = 0
    for i, idx in enumerate(path):
        parent_fpr = fingerprint(k)
        k, c = ckd_priv(k, c, idx)
        depth = i + 1
        child = idx
    return {"k": k, "c": c, "xfp": xfp, "parent_fpr": parent_fpr, "depth": depth, "child": child}


# ---------------------------------------------------------------- addresses

def wrapper_for(kind: str) -> tuple[str, str]:
    return {"p2wpkh": ("wpkh(", ")"), "p2sh-p2wpkh": ("sh(wpkh(", "))"), "p2pkh": ("pkh(", ")")}[kind]


def address_for(kind: str, pubkey: bytes) -> str:
    h160 = hash160(pubkey)
    if kind == "p2wpkh":
        return bech32_encode("bc", 0, h160)
    if kind == "p2sh-p2wpkh":
        return b58check(b"\x05" + hash160(b"\x00\x14" + h160))
    return b58check(b"\x00" + h160)


def first_address(acct: dict, kind: str) -> str:
    k_recv, c_recv = ckd_priv(acct["k"], acct["c"], 0)
    k0, _ = ckd_priv(k_recv, c_recv, 0)
    return address_for(kind, ser_p(_mul(k0)))


# ---------------------------------------------------------------- self-test

def _fail(msg: str):
    sys.exit("FAIL " + msg)


def run_tests(wordlist_path: Path) -> None:
    for msg, want in {b"": "9c1185a5c5e9fc54612808977ee8f548b2258d31",
                      b"abc": "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc",
                      b"a" * 100: None}.items():
        got = _ripemd160(msg).hex()
        if want and got != want:
            _fail(f"ripemd160 fallback {msg!r}: {got}")
        try:
            if got != hashlib.new("ripemd160", msg).hexdigest():
                _fail(f"ripemd160 fallback differs from OpenSSL on {msg!r}")
        except ValueError:
            pass
    print("PASS ripemd160 fallback")

    a = bech32_encode("bc", 0, hash160(ser_p(G)))
    if a != "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4":
        _fail("bech32 BIP173 vector: " + a)
    print("PASS bech32")

    if desc_checksum("raw(deadbeef)") != "raw(deadbeef)#89f8spxm":
        _fail("descriptor checksum: " + desc_checksum("raw(deadbeef)"))
    print("PASS descriptor checksum")

    words = ["abandon"] * 23 + ["art"]
    seed = mnemonic_to_seed(words, "TREZOR")
    expect = bytes.fromhex(
        "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd30971"
        "70af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8"
    )
    if seed != expect:
        _fail("seed vector")
    k, c = master_from_seed(seed)
    xprv = encode_ext(XPRV_VER, 0, b"\x00" * 4, 0, c, b"\x00" + k.to_bytes(32, "big"))
    if not xprv.startswith("xprv9s21ZrQH143K32qBag"):
        _fail("master xprv prefix: " + xprv)
    print("PASS BIP39 seed + master xprv (24 words, TREZOR passphrase)")

    seed = mnemonic_to_seed(["abandon"] * 11 + ["about"], "")
    for path_s, want in [
        ("m/84h/0h/0h", "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"),
        ("m/49h/0h/0h", "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf"),
        ("m/44h/0h/0h", "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"),
    ]:
        path = parse_path(path_s)
        got = first_address(derive_account(seed, path), validate_path(path))
        if got != want:
            _fail(f"{path_s}: got {got}, want {want}")
        print(f"PASS {path_s} first address")

    acct = derive_account(seed, parse_path("m/84h/0h/0h"))
    xpub = encode_ext(XPUB_VER, acct["depth"], acct["parent_fpr"], acct["child"], acct["c"], ser_p(_mul(acct["k"])))
    if xpub != "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V":
        _fail("m/84h/0h/0h account xpub: " + xpub)
    print("PASS account xpub encoding")

    for bad in ("m/86h/0h/0h", "m/48h/0h/0h/2h", "m/84h/1h/0h", "m/84h/0h", "m/84/0h/0h"):
        try:
            validate_path(parse_path(bad))
        except SystemExit:
            continue
        _fail(f"path {bad} should have been rejected")
    for ok in ("49H/0H/0H", "m/49'/0'/0'", "M/84h/0h/0h"):
        validate_path(parse_path(ok))
    print("PASS path validation")

    if wordlist_path.exists():
        wl = load_wordlist(wordlist_path)
        for nbytes in (16, 20, 24, 28, 32):
            for fill in (0x00, 0x7F, 0xFF, 0xA5):
                ent = bytes([fill]) * nbytes
                if mnemonic_to_entropy(entropy_to_mnemonic(ent, wl), wl) != ent:
                    _fail(f"checksum round trip, {nbytes * 3 // 4} words")
        print("PASS checksum round trip for 12/15/18/21/24 words")
    else:
        print(f"SKIP wordlist checks ({wordlist_path} not found)")
    print("ALL TESTS PASSED")


# ---------------------------------------------------------------- main

def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--wordlist", default=str(Path(__file__).with_name("english.txt")))
    ap.add_argument("--words", help="NOT recommended: leaks into shell history / process list")
    ap.add_argument("--passphrase", default=None, help="NOT recommended: use --ask-passphrase")
    ap.add_argument("--ask-passphrase", action="store_true", help="prompt for the BIP39 passphrase (hidden)")
    ap.add_argument("--path", default="m/84h/0h/0h", help="account path")
    ap.add_argument("--test", action="store_true", help="run built-in vectors and exit")
    ap.add_argument("--xprv", action="store_true", help="also print account xprv (offline only)")
    args = ap.parse_args()

    if args.test:
        run_tests(Path(args.wordlist))
        return

    path = parse_path(args.path)
    kind = validate_path(path)
    wordlist = load_wordlist(Path(args.wordlist))

    if args.words:
        print("warning: --words leaks the seed into shell history and the process list", file=sys.stderr)
        raw = args.words
    else:
        raw = getpass.getpass("seed words (hidden): ")
    words = nfkd(raw).strip().lower().split()
    mnemonic_to_entropy(words, wordlist)

    if args.ask_passphrase:
        passphrase = getpass.getpass("BIP39 passphrase (hidden, empty for none): ")
    else:
        if args.passphrase:
            print("warning: --passphrase leaks into shell history and the process list", file=sys.stderr)
        passphrase = args.passphrase or ""
    seed = mnemonic_to_seed(words, passphrase)

    acct = derive_account(seed, path)
    xfp = acct["xfp"].hex()
    body = fmt_path(path)
    xpub = encode_ext(XPUB_VER, acct["depth"], acct["parent_fpr"], acct["child"], acct["c"], ser_p(_mul(acct["k"])))
    open_, close = wrapper_for(kind)

    print("path: m/" + body)
    print("script type:", kind)
    print("master fingerprint (xfp):", xfp)
    print("xpub:")
    print(xpub)
    print()
    print("Core watch-only descriptors (import both: receive and change):")
    for chain in (0, 1):
        print(desc_checksum(f"{open_}[{xfp}/{body}]{xpub}/{chain}/*{close}"))
    print()
    print("first receive address (index 0):")
    print(first_address(acct, kind))

    if args.xprv:
        xprv = encode_ext(
            XPRV_VER, acct["depth"], acct["parent_fpr"], acct["child"], acct["c"],
            b"\x00" + acct["k"].to_bytes(32, "big"),
        )
        print()
        print("ACCOUNT xprv (this spends the coins, offline only):")
        print(xprv)
        print()
        print("Core signing descriptors (receive and change):")
        for chain in (0, 1):
            print(desc_checksum(f"{open_}[{xfp}/{body}]{xprv}/{chain}/*{close}"))
        print()
        print("Delete this wallet after signing. Do not save this output.")
    else:
        print()
        print("xprv not printed. Pass --xprv on an air-gap box if you need signing descriptors.")


if __name__ == "__main__":
    main()