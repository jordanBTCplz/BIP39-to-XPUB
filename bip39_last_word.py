#!/usr/bin/env python3
"""
Offline helper: 23 BIP39 words + 3 extra bits -> 32-byte entropy and word 24.

Put the official English wordlist next to this file as english.txt
(one word per line, 2048 lines):
  https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt
  sha256 2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda
The script verifies this hash and refuses to run on any other file.

The 3 extra bits: write them as 0/1 (101), as coin flips with H=1 and T=0 (HTT),
or as a number 0-7.

Usage (offline):
  python3 bip39_last_word.py
  python3 bip39_last_word.py --words "word1 word2 ... word23" --bits 101
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

WORDLIST_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"


def load_wordlist(path: Path) -> list[str]:
    try:
        raw = path.read_bytes()
    except OSError as e:
        sys.exit(f"cannot read wordlist: {e}")
    if hashlib.sha256(raw).hexdigest() != WORDLIST_SHA256:
        sys.exit(f"{path}: sha256 is not the official BIP39 English wordlist ({WORDLIST_SHA256})")
    words = [line.strip() for line in raw.decode("utf-8").splitlines() if line.strip()]
    if len(words) != 2048:
        sys.exit(f"{path} must contain exactly 2048 words, found {len(words)}")
    return words


def parse_bits(text: str) -> int:
    text = text.strip().lower().replace(" ", "")
    text = text.replace("h", "1").replace("t", "0")  # coin flips: H=1, T=0
    if text.isdigit() and len(text) == 1 and 0 <= int(text) <= 7:
        return int(text)
    if len(text) == 3 and all(c in "01" for c in text):
        return int(text, 2)
    sys.exit("bits must be 3 coin flips like 101 / HTT (H=1, T=0), or a number 0-7")


def words_to_index(words: list[str], wordlist: list[str]) -> list[int]:
    index_of = {w: i for i, w in enumerate(wordlist)}
    out = []
    for n, w in enumerate(words, start=1):
        if w not in index_of:
            sys.exit(f"word {n} is not on the list: {w}")
        out.append(index_of[w])
    return out


def entropy_from_23(indexes: list[int], extra_bits: int) -> bytes:
    n = 0
    for idx in indexes:
        n = (n << 11) | idx
    n = (n << 3) | extra_bits
    return n.to_bytes(32, "big")


def main() -> None:
    parser = argparse.ArgumentParser(description="Compute BIP39 word 24 from 23 words + 3 bits")
    parser.add_argument("--wordlist", default="english.txt")
    parser.add_argument("--words", help="23 words, space-separated")
    parser.add_argument("--bits", help="3 bits: 101, HTT (H=1, T=0), or 0-7")
    args = parser.parse_args()

    wordlist = load_wordlist(Path(args.wordlist))

    raw_words = args.words or input("23 words: ")
    words = raw_words.strip().lower().split()
    if len(words) != 23:
        sys.exit(f"need exactly 23 words, got {len(words)}")

    extra = parse_bits(args.bits or input("3 extra bits (e.g. 101, or HTT with H=1 T=0, or 0-7): "))
    entropy = entropy_from_23(words_to_index(words, wordlist), extra)
    digest = hashlib.sha256(entropy).digest()
    checksum = digest[0]  # first 8 bits
    last_index = (extra << 8) | checksum
    last_word = wordlist[last_index]

    print()
    print("32-byte entropy (hex):")
    print(entropy.hex())
    print()
    print("SHA-256 of those 32 bytes:")
    print(digest.hex())
    print(f"first 8 bits / first byte: {checksum:02x}  ({checksum:08b})")
    print()
    print(f"word 24 index: {last_index}")
    print(f"word 24: {last_word}")
    print()
    print("full mnemonic:")
    print(" ".join(words + [last_word]))
    print()
    print("Check the hash yourself if you want:")
    print("  python3 -c \"import hashlib,sys; print(hashlib.sha256(bytes.fromhex(sys.argv[1])).hexdigest())\" " + entropy.hex())


if __name__ == "__main__":
    main()
