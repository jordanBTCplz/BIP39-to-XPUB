# Instructions: BIP39 words → Core watch-only

Same steps for a $10 test and for a real plate. For a real plate: no photos
of slips, paper, or the terminal once words are on screen.

There are three roles, not just one computer:

1. **Meatspace** — bag of BIP39 word slips (default) or casino dice
2. **Offline signer** — a laptop with a clean install of linux that boots **Tails**
    (or equivalent) and never joins a network this session
3. **Online node** — Bitcoin Core. It only ever sees an xpub / descriptor.
   Never the 24 words.

## 0. What you should have

- Any PC that can boot from USB
- A Tails USB verified against https://tails.net
- A **second** USB ("tools") with:
  - `bip39_last_word.py`
  - `bip39_account.py`
  - `english.txt` 
  - `lookup.py` and `bip39-dice-worksheet.pdf` **only if you use dice**
  - these instructions (optional)
- A **third** USB if you want the xpub on a separate data stick
- Printer, scissors, container for slips (default path)
- Casino dice + pen **only for the dice path**
- A Bitcoin Core node on its own machine

Do not put the 24 words on any USB. The xpub rides the data stick, not the
tools stick, if you have both.

`english.txt` check (once on a hot machine, then copy the file):

    sha256sum english.txt

Must be `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`.

---

## 1. Boot the offline laptop into Tails

1. Laptop **off**. Tails stick in a port on the laptop itself (hubs are flaky for boot).
2. Power on and open the firmware boot menu (Esc, F12, F10, F9, F2, or Del).
   If you land on `grub>` you were late — type `exit` or hold power and try again.
3. Pick the **USB / UEFI** entry for Tails.
4. Welcome screen: Persistent Storage **OFF**. Do **not** join Wi-Fi.

Blue desktop = offline enough. After boot, Tails runs from RAM; you can unplug the Tails stick if you need the port.

---

## 2. Terminal + tools USB

1. Plug the "tools" stick.
2. Open Terminal.
3. Mount point:

    ls /media/amnesia
    cd /media/amnesia/LABEL
    ls

`LABEL` is the stick's name. If `cd` fails, you probably typed only the name. Use the full path `/media/amnesia/LABEL`.

Some live USBs use `/run/media/USERNAME/LABEL` instead.

4. Prove the account script:

    python3 bip39_account.py --test

You want every line to say `PASS` and the last line to say `ALL TESTS PASSED`. Any `FAIL`
(including "wordlist not found") means stop. The built-in test vectors are public test keys, not yours.

---

## 3. Entropy (default: bag)

1. Print the hashed `english.txt`. Cut each word onto its own slip.
2. Mix. Draw one, write it, **put it back**, mix. Do that **23 times**.
3. Repeat words are allowed for BIP39. If you draw the same word from two random pulls, that's ok.
4. Get **3 extra bits** on paper (`000` … `111`) with coins or a 1-4 die
   (`1=00 2=01 3=10 4=11`). This is **not** a 24th drawn word.

Skip section 4. Go to section 5. You do not need `rows.txt` or `lookup.py`.

---

## 4. Dice path (optional)

Mapping: **1=00  2=01  3=10  4=11**. **5 and 6 = reroll.** Cocked die = reroll.

- Keep left-to-right order as they landed.
- Print `bip39-dice-worksheet.pdf` and fill **23 rows** of 11 bits.
- Then you will roll **3 more bits**. Write those on paper. They do **not** go in `rows.txt`.

- What you will type looks like this. (fake bits — do not use):
 ```
    01001110101
    11010001100
    00101101011
```

1. `nano rows.txt` — 23 lines, exactly 11 characters of `0` and `1`. No leftover-bits line.
2. `wc -l rows.txt` must say `23`.
3. `python3 lookup.py`
4. Spot-check first, middle, and last row against paper. Same word twice is allowed.

Then section 5.

---

## 5. Word 24

    python3 bip39_last_word.py

- type the 23 words with spaces between them
- Extra bits: the three `0`/`1`s from paper (example `000` or `101`; coin flips also work as `HTT` with H=1, T=0)
- Write **word 24** and the full 24-word seed on paper

---

## 6. xpub + first address

    python3 bip39_account.py

Type all **24** words (or your 12/15/18/21 words if you already had a valid phrase). The prompt is
**hidden**: nothing shows while you type, like a password. A word that is not on the list, or a bad
checksum, stops the script. A typo that happens to be another valid word can still slip past the
checksum, so do step 6b before you trust the result.

Script default is no passphrase and the path `m/84h/0h/0h`. For nested SegWit or legacy add
`--path m/49h/0h/0h` or `--path m/44h/0h/0h`. Any other path is refused.

There is a passphrase option: `--ask-passphrase` (hidden prompt). Do not use it unless that extra secret is written down and backed up, but **not together** with the plate. Enter the same passphrase in Electrum when you check in 6b, or leave it blank in both. Avoid `--passphrase` and `--words`: they put your secret in the shell history and the process list.

Copy onto paper or a **public-only** text file on the data USB (not the 24 words):

- path (`m/84h/0h/0h`)
- master fingerprint (xfp)
- **xpub**
- both descriptor lines (receive `…/0/*` and change `…/1/*`), each already ending in `#checksum`
- first receive address (`bc1q…`)

Do **not** pass `--xprv` unless this box is air-gapped and you need a signing descriptor. Address 0 is `m/84h/0h/0h/0/0`. Confirm it in Electrum (section 6b) before sending.

**If** you used the dice path, delete `rows.txt` before you unplug the stick:

    rm rows.txt

Those 23 lines are almost the whole seed. Do not leave them on the USB.
Do not copy that file to the online machine. The words live on paper.
The USB should only carry the xpub after this. This is one of the main reasons I
decided to make pulling slips of paper the default. This is a risk. **Be aware of it**

---

## 6b. Check address 0 in Electrum (same offline Tails session)

This is the independent check. Do it before anything is sent.

1. Open Electrum (it ships in Tails). Create a new wallet and choose to restore from an existing
   seed. In the seed dialog open **Options**, tick **BIP39 seed**, then type the same words. If you
   used a passphrase, Electrum may label that field "Extend this seed with custom words".
2. When Electrum asks for the script type and derivation path, pick **native segwit (p2wpkh)** and
   `m/84'/0'/0'`. (For `--path m/49h/0h/0h` pick p2wpkh-p2sh and `m/49'/0'/0'`; for
   `m/44h/0h/0h` pick legacy p2pkh and `m/44'/0'/0'`.) Menu names differ a little between
   Electrum versions.
3. Open the Addresses tab. The first receiving address must be identical to the one the script
   printed, character for character.
4. Electrum shows the account key as `zpub…`, not `xpub…`. That is the same key with different
   version bytes. Do not compare those strings. The address is the check.

If the addresses differ: stop. Do not import anything into Core and do not send anything.
Re-check the words, the path and the passphrase first.

---

## 7. Online node (Bitcoin Core)

Words stay on paper. Only the descriptor moves.

1. Create a **watch-only** descriptor wallet (no private keys, blank):

       bitcoin-cli createwallet "watch" true true "" false true

   (arguments: disable_private_keys, blank, no passphrase, no avoid_reuse, descriptors)

2. Import both descriptor lines exactly as the script printed them. They already end in `#checksum`.
   You can run `getdescriptorinfo` on each as a cross-check; it should return the same checksum.
   `"active": true` is required, or `getnewaddress` will not use them:

       bitcoin-cli -rpcwallet=watch importdescriptors '[
         {"desc": "<receive line, ends #checksum>", "active": true, "internal": false, "timestamp": "now"},
         {"desc": "<change line, ends #checksum>",  "active": true, "internal": true,  "timestamp": "now"}]'

   Use `"timestamp": "now"` for a new wallet with no coins. If address 0 has already received coins,
   use `"timestamp": 0` so Core rescans (slow; a pruned node may refuse it).
3. `bitcoin-cli -rpcwallet=watch getnewaddress "" bech32` must print script address 0 on a fresh
   wallet (use `p2sh-segwit` for 49h, `legacy` for 44h). If not, stop.

Send a small test amount to that `bc1q`. Confirm it in Core before any serious balance.

---

## 8. Shut down

- Before real words: locking the screen is fine.
- After words: **Shutdown**. Tails menu → Shutdown. Wait for the memory-wipe line.

Tails does not keep scripts in RAM after shutdown. The tools USB does.

---

## Spend later (outline)

These scripts do not sign. They do not need to.

Online Core (watch-only) builds a PSBT (`walletcreatefundedpsbt`). On Tails, open Electrum and
restore the wallet from the 24 words for that session only (as in 6b). Load the PSBT and
**read the destination address, the amount and the change address on screen before you sign**.
The change output should go to an address of your own wallet. Sign, then export the signed result.
Back on the online machine, `finalizepsbt` (if it is a PSBT) and `sendrawtransaction`, or use
Core's GUI. Wipe / shut down. Do not leave the seed on disk.

How the data crosses the gap matters. Data going out of the offline machine (an xpub, a signed
transaction) is public and low risk. Data going in is the risk. QR codes are the safest way in:
Electrum can scan and show them, and Core cannot draw them, so render the PSBT's base64 on the
online side with a small tool such as `qrencode`. A USB stick that has touched the online machine
is the riskiest thing to plug into the signer. If you must use USB, use a dedicated stick that only
ever carries PSBTs, never the tools stick.

Do **not** use `--xprv` for this. That flag dumps a spending key.
It is untested. Leave it alone.

---

## Command cheat sheet

    ls /media/amnesia
    cd /media/amnesia/LABEL
    ls
    python3 bip39_account.py --test
    python3 bip39_last_word.py
    python3 bip39_account.py
    python3 bip39_account.py --ask-passphrase
    python3 bip39_account.py --path m/49h/0h/0h

Dice path only:

    wc -l rows.txt
    python3 lookup.py
    rm rows.txt

Flags are two short ASCII dashes: `--test` not a word-processor dash.
