# Security

These scripts are small, stdlib-only helpers for an air-gapped machine. They are not a wallet.
They are **unaudited**. `--test` checks them against published test vectors, which catches
derivation bugs but is not a review.

## Do

- Generate entropy with physical dice (1–4 only; reroll 5 and 6), or with a bag of slips you
  have mixed very well.
- Run only on an offline OS (Tails with persistence off, or equivalent).
- Verify `english.txt`:
  `sha256sum english.txt`
  expected `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`
  (the scripts check this too and refuse any other file).
- Run `python3 bip39_account.py --test` before any real seed. It must end with `ALL TESTS PASSED`.
- Confirm address 0 in Electrum on the same offline machine before sending. Electrum shows the key
  as `zpub`/`ypub`, so compare the address, not the key text. After importing into Core, confirm
  that Core's first `getnewaddress` is the same address.
- Keep the 24 words on paper/steel. Delete `rows.txt`. Do not photograph a real plate.
- Type the words at the prompt (visible by default; use `--hidden` if anyone could see or photograph
  your screen) and use `--ask-passphrase` for any passphrase (always hidden). Avoid `--words` and `--passphrase`: they
  leak into shell history and the process list.
- Use `--xprv` only on the air-gap box. Never paste an xprv into a hot machine.
- Move data **into** the offline machine by QR where you can. A USB stick that has touched an
  online machine is the riskiest thing to plug into the signer.

## Do not

- Run this in a browser or on a phone, and do not type the words into a phone wallet to "check"
  them, if that device has ever been online.
- Trust a download of these files from anywhere but a repo whose history you checked.
- Treat a matching xpub as proof the printed address is correct. An earlier bug hashed `m/84h/0h/0h/0` instead of `/0/0`. The xpub can be right while address 0 is wrong. Always compare address 0.

## What this is not

Not multisig. Not a PSBT signer. Not a substitute for reviewing the Python yourself.
Not hardened: the elliptic-curve math is plain Python and not constant-time. That is fine for a
one-shot run on an air-gapped machine. Do not use it on a shared or networked computer.
