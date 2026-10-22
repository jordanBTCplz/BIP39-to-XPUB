# not-yeti

BIP39 words → account **xpub** so Bitcoin Core can **watch**.

This tool is for someone that wants to generate their own entropy and a BIP39 plate, the extra
code here is two small stdlib Python scripts. Linux, Tails, and Core require the
same trust you would need for an offline Core-only workflow. Electrum
is the independent check that those scripts walked BIP32 the same way
libsecp does. **If you do not care about BIP39, use Core and skip this
repo**.

This is not a signing wallet. The only job this tool has been tested for is:

**24 words → BIP84 xpub + watch-only descriptor + receive address 0.**

`--xprv`, other paths, passphrases and spending have **not**
been treated as a finished product. Sign in Electrum (or your trusted signer) 
on an air-gapped machine booted into Tails. The core online node only ever sees an xpub from this tool.

Do not put real money on an address that has only been printed by
`bip39_account.py`. These files are not formally reviewed.

This tool does not use libsecp. Electrum (and Core) do. I only even bring 
Electrum in as a grader because it is a well-regarded software that takes 
BIP39 words in and uses libsecp for BIP32. Electrum ships in Tails so you 
get it anyway with no additional download. Libsecp is a much
larger library than we need here; we only walk BIP32 far enough to print
an xpub and address 0. Grade this script offline against Electrum or another BIP39 wallet
you trust offline that uses libsecp. Once you have confirmed that the 24 words you 
generated produce the same XPUB and receive address that our script prints, then you
can paste the XPUB into Core as your watch only node.

If the same 24 words and path produce the **same xpub and address 0** in
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
3. 24 words → BIP84 **xpub** + Core watch-only descriptor + address 0
   (`bip39_account.py`)

No pip. No network. Python 3 stdlib only.

## Files

| File | Job | Required? |
|---|---|---|
| `english.txt` | Official BIP-39 English list | Hash it. Need it for last-word / lookup |
| `lookup.py` | `rows.txt` (23 × 11 bits) → words | **Dice path only** |
| `bip39_last_word.py` | 23 words + 3 bits → word 24 | Default path |
| `bip39_account.py` | 24 words → xpub / `wpkh` / address 0 | Default path |
| `bip39-dice-worksheet.pdf` | 11-bit dice sheet | Dice path only |
| `instructions.md` | Tails + Core walkthrough | Read it |

Already have a valid 24-word phrase? Skip both small scripts. Run `bip39_account.py` and type the 24 words in.

## Wordlist check

    sha256sum english.txt

Must be:

    2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda

Source: https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt

Indexes are **0-based** (`abandon` = 0). GitHub line numbers are 1-based.

## Default: bag of words

1. Print `english.txt` (the hashed copy). Cut into 2048 slips.
2. Mix well. Draw one slip, write the word, **put it back**, mix again.
3. Do that **23 times**. Repeats are legal BIP39.
4. Get **3 extra bits** (three coin flips, or a 1-4 die mapping
   1=00 2=01 3=10 4=11 and keep three bits). Write them as 010 etc.
5. On the offline box: `python3 bip39_last_word.py` with the 23 words and
   those 3 bits. Write word 24.
6. `python3 bip39_account.py` with all 24 words. Default is an empty
   passphrase. There is a `--passphrase` flag. Do not use it unless that
   extra secret is written down and backed up just like your 24 words and **NOT Together**. That flag is untested as of now.

## Optional: dice

- Faces **1-4** only. **5 and 6 = reroll.**
- 1=00  2=01  3=10  4=11
- Keep left-to-right order as they landed.
- 23 rows x 11 bits in `rows.txt`. Extra 3 bits do **not** go in that file.
- `python3 lookup.py` then last-word then account.

See `instructions.md` section "Dice path."

## Offline commands

    python3 bip39_account.py --test

Must print `PASS`. Vector: 23x `abandon` + `art`, passphrase `TREZOR`.
Master xprv starts `xprv9s21ZrQH143K32qBag`.

Default bag path:

    python3 bip39_last_word.py
    python3 bip39_account.py

Dice path adds `python3 lookup.py` first.

Default path `m/84h/0h/0h`. Script default is **no passphrase**.
`--xprv` exists. **Untested as a daily signer**.

Address 0 is `m/84h/0h/0h/0/0`. Core:

    wpkh([xfp/84h/0h/0h]xpub.../0/*)
    wpkh([xfp/84h/0h/0h]xpub.../1/*)

Confirm address 0 against Sparrow / Core **before** sending.

## What this will not do

- Act like a wallet
- PSBT signing
- Multisig descriptors
- Undo a mistyped word
- Replace a second-program check

## License

MIT. Read the scripts. Run `--test`. Compare address 0 on a second tool.
