# IPA decryptor

Decrypt FairPlay-encrypted apps using a 16-byte credential
for the account that owns each IPA. [Credential retrieval](credential-retrieval/README.md)
gets it from a supported jailbroken device and writes
`credential.bin` to the chosen output directory.

Decryption runs on macOS and Linux.

Supports version-3 and version-5 SUPF, 448-byte and 440-byte SINF `priv`
records, and encrypted arm64 Mach-O slices. A 440-byte record must end in
eight zero bytes.

## Set up

From this directory, with Python 3.9+:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
```

The decryptor is pure Python. On macOS, `make` builds the
credential-retrieval bundle and requires Xcode and `ldid`.

## Decrypt

```sh
python decrypt.py /path/to/encrypted.ipa /path/to/decrypted.ipa \
  --credential /path/to/credential.bin
```

If neither `--credential` nor `--region` is supplied, the tool reads
`credential.bin` beside `decrypt.py`. The output path must not exist.

### Select a credential by region

For a bot that already knows the acquiring account's region, store each
credential in a region/type directory beside `decrypt.py`:

```text
credentials/
  us/appstore/credential.bin
  gb/appstore/credential.bin
  us/arcade/credential.bin
```

```sh
python decrypt.py encrypted.ipa decrypted.ipa --region us
python decrypt.py arcade.ipa arcade-decrypted.ipa --region us --credential-type arcade
```

`--region` accepts a two-letter code, case-insensitively. The default type is
`appstore`. Use `--credentials-dir /path/to/credentials` to change the store
location. Selection is explicit: the tool reads only the selected file and
never searches other regions or falls back to `credential.bin`. A missing,
invalid, or nonmatching credential fails the operation.

Each region/type slot must contain the credential for the Apple Account used
to acquire that IPA. A region is a label, not a substitute for account ownership.
If multiple accounts use the same region, give them separate credential stores
and select the store with `--credentials-dir`. `--credential` and `--region`
are mutually exclusive; omitting both retains the original single-file mode.

The bot can pass its chosen `job.region` directly as `--region`. This repository
does not change the bot or switch Apple Accounts on a device. See
[credential retrieval](credential-retrieval/README.md#direct-ssh-and-tailscale)
for saving a credential over SSH into the matching region directory.
The `credentials/` directory is excluded from Git.

The decryptor uses each IPA's SINF and SUPF records to derive page keys,
decrypt its encrypted arm64 pages, and clear `cryptid`.

## Checks

`make lint` runs the pinned Python checks. `make test` runs synthetic IPA and
mocked SSH/retrieval tests; it does not connect to a device.
