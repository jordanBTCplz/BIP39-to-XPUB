# not-yeti

BIP39 words → account **xpub** so Bitcoin Core can **watch**.

This tool is for someone that wants to generate their own entropy and a BIP39 plate, the extra
code here is two small stdlib Python scripts (plus an optional third for dice). Linux, Tails, and Core require the
same trust you would need for an offline Core-only workflow. Electrum
is the independent check that those scripts walked BIP32 the same way
libsecp does. **If you do not care about BIP39, use Core and skip this
repo**.

This is not a signing wallet. `bip39_account.py` does one job:

**12/15/18/21/24 words → account xpub + watch-only descriptors (receive and change, each with its
`#checksum`) + receive address 0.**

Paths: BIP84 `m/84h/0h/0h` (default, `bc1q…`), BIP49 `m/49h/0h/0h` (`3…`) and BIP44
`m/44h/0h/0h` (`1…`). Mainnet only. Any other path is refused on purpose. The words are typed
at a hidden prompt.

`python3 bip39_account.py --test` checks the code against published test vectors: BIP39 seed
with a passphrase, first addresses for all three paths, bech32, RIPEMD-160, the descriptor
checksum, the path rules, and the BIP39 checksum for every word count. Passing means the code
matches those vectors. It does not make the scripts reviewed, and it does not replace the
Electrum check below.

`--xprv` and spending have **not** been treated as a finished product. Sign in Electrum (or your
trusted signer) on an air-gapped machine booted into Tails. The core online node only ever sees an
xpub from this tool.

Do not put real money on an address that has only been printed by
`bip39_account.py`. These files are not formally reviewed.

This tool does not use libsecp. Electrum (and Core) do. I only even bring
Electrum in as a grader because it is a well-regarded software that takes
BIP39 words in and uses libsecp for BIP32. Electrum ships in Tails so you
get it anyway with no additional download. Libsecp is a much
larger library than we need here; we only walk BIP32 far enough to print
an xpub and address 0. Grade this script offline against Electrum (steps in
`instructions.md`, section 6b). Once you have confirmed that the 24 words you
generated produce the same receive address 0 that our script prints, then you
can import the descriptors into Core as your watch only node.

**Compare addresses, not key strings.** Electrum shows a native SegWit key as `zpub…` (nested
SegWit as `ypub…`). It is the same key with different version bytes, so the text will not match the
`xpub…` this script prints even when everything is right. Address 0 is the check.

If the same words and path produce the **same address 0** in
this script and in Electrum, you are not looking at a malicious address.
The scripts are small and do one job. A match does **not** fix a word you
wrote down wrong on your backup.

The tested check is address 0 and the account xpub. Later receive
and change addresses come from Core once that xpub is imported.
You do not need this script to print addresses beyond 0.

## Why words-in-a-bag is the default

Dice can be slightly "fairer" bits. The expensive mistake is not a slightly 
unfair bag. It is transcribing 253 bits of dice rolls into 23 words.
**How you generate your entropy is a decision you should make. Both options 
in this guide have trade-offs**. I defaulted to slips of paper in a bag because 
the ethos of this tool is minimization of trust on software. Generating a 23 words
from dice and paper only without `lookup.py` is exhausting, but can be done.

A bag is only as random as your mixing: folded, sticky or just-returned slips bias the
draw. If you do not trust your mixing, use dice.

Default entropy here is: print the official wordlist, cut slips, draw
**23 words**, put each slip **back** (repeats are allowed), then get **3
extra bits** (coins or one die). `lookup.py` is not required.

Dice protocol is still in `instructions.md` if you want it.

## Trust model

After the same 24 words print the same address 0 in this script and in
Electrum, the derivation is as checked as these files get. Core is what
you use to watch that xpub afterward.

What still loses coins: sloppy draws, leftover bits in the wrong place,
photos, Wi-Fi while words exist, passphrase in one tool and not the other.

## What the files do

1. Optional: dice rows → first 23 words (`lookup.py`)
2. 23 words + 3 extra bits → word 24 (`bip39_last_word.py`)
3. 24 words → **xpub** + Core watch-only descriptors + address 0
   (`bip39_account.py`)

No pip. No network. Python 3 stdlib only.

## Files

| File | Job | Required? |
|---|---|---|
| `english.txt` | Official BIP-39 English list | Hash it. Every script needs it |
| `lookup.py` | `rows.txt` (23 × 11 bits) → words | **Dice path only** |
| `bip39_last_word.py` | 23 words + 3 bits → word 24 | Default path |
| `bip39_account.py` | 24 words → xpub / descriptors / address 0 | Default path |
| `bip39-dice-worksheet.pdf` | 11-bit dice sheet | Dice path only |
| `instructions.md` | Tails + Core walkthrough | Read it |

Already have a valid 12/15/18/21/24-word phrase? Skip both small scripts. Run `bip39_account.py` and type the words in.

## Wordlist check

    sha256sum english.txt

Must be:

    2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda

Source: https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt

The scripts check this hash themselves and refuse any other file.

Indexes are **0-based** (`abandon` = 0). GitHub line numbers are 1-based.

## Default: bag of words

1. Print `english.txt` (the hashed copy). Cut into 2048 slips.
2. Mix well. Draw one slip, write the word, **put it back**, mix again.
3. Do that **23 times**. Repeats are legal BIP39.
4. Get **3 extra bits** (three coin flips, or a 1-4 die mapping
   1=00 2=01 3=10 4=11 and keep three bits). Write them as 010 etc.
   (For coin flips, `bip39_last_word.py` reads H as 1 and T as 0.)
5. On the offline box: `python3 bip39_last_word.py` with the 23 words and
   those 3 bits. Write word 24.
6. `python3 bip39_account.py` with all 24 words (typed at a hidden prompt). Default is an empty
   passphrase. To use one, run it with `--ask-passphrase` (hidden prompt). Do not use a passphrase
   unless that extra secret is written down and backed up just like your 24 words and **NOT Together**.
   Enter the same passphrase in Electrum when you check. Avoid `--passphrase` and `--words`: they
   put your secret in the shell history and the process list. The passphrase step of the derivation is
   covered by `--test`; typing one is otherwise lightly tested, so check address 0 in Electrum.

## Optional: dice

- Faces **1-4** only. **5 and 6 = reroll.**
- 1=00  2=01  3=10  4=11
- Keep left-to-right order as they landed.
- 23 rows x 11 bits in `rows.txt`. Extra 3 bits do **not** go in that file.
- `python3 lookup.py` then last-word then account.

See `instructions.md` section "Dice path."

## Offline commands

    python3 bip39_account.py --test

Must end with `ALL TESTS PASSED`. Any `FAIL` line, or a missing `english.txt`, is a failure. The vectors
include 23x `abandon` + `art` with passphrase `TREZOR` (master xprv starts `xprv9s21ZrQH143K32qBag`)
and the first-address vectors for the well-known test phrase `abandon` x11 + `about`
(empty passphrase) on all three paths.

Default bag path:

    python3 bip39_last_word.py
    python3 bip39_account.py

Dice path adds `python3 lookup.py` first.

Default path `m/84h/0h/0h`. For nested SegWit or legacy use `--path m/49h/0h/0h` or
`--path m/44h/0h/0h`. Script default is **no passphrase**.
`--xprv` exists. **Untested as a daily signer**.

Address 0 is `m/84h/0h/0h/0/0`. The script prints these for Core (each with its `#checksum`
added; shown here without it):

    wpkh([xfp/84h/0h/0h]xpub.../0/*)
    wpkh([xfp/84h/0h/0h]xpub.../1/*)

(`sh(wpkh(...))` for 49h, `pkh(...)` for 44h.)

Confirm address 0 in Electrum **before** sending, and again against Core's first
`getnewaddress` after you import the descriptors.

## What this will not do

- Act like a wallet
- PSBT signing
- Multisig descriptors
- Testnet, or any path other than 84h / 49h / 44h on coin type 0h
- Undo a mistyped word
- Replace a second-program check
- Run safely on a shared or networked machine (the EC math is plain Python, not constant-time)

## License

MIT. Read the scripts. Run `--test`. Compare address 0 on a second tool.
