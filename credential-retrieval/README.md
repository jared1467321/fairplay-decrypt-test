# Credential retrieval

Retrieve a reusable 16-byte FairPlay account credential from a jailbroken
device using direct SSH (including Tailscale) or USB SSH. The host needs Python
and OpenSSH. USB mode additionally needs `idevice_id` and `iproxy`.

Supports iOS 10+.

## Retrieve

Connect one paired, jailbroken device with root SSH key access. Install at
least one App Store app on that device. From the project root:

```sh
make
python3 credential-retrieval/retrieve.py --output-dir /path/to/new-output-directory
```

The retriever uses the first installed app with a supported license. To
select a particular account, pass `--ipa /path/to/app.ipa` or
`--sinf /path/to/license.sinf`; an installed app under that account is still
required. If an IPA has distinct license selectors, specify one with
`--sinf-member`. Set `--ssh-port` if the USB SSH tunnel does not use port 2222.
The output directory must not exist; it receives `credential.bin` for use
with `decrypt.py --credential`.

## Apple Arcade

Apple Arcade apps need a different credential from regular App Store apps.
The normal credential decrypts regular apps, and the Arcade credential
decrypts Arcade apps. You need both to decrypt both types. Each credential
works with apps from the Apple Account it came from.

To retrieve an Arcade credential, pass an Arcade IPA with `--ipa` and have
an Arcade app from that account installed on the device.

Build on a Mac with Xcode and `ldid`.

## Direct SSH and Tailscale

Build the device helper bundle on a Mac or a macOS GitHub Actions runner,
then copy the entire `credential-retrieval/build/bundle` directory to the
Linux/VPS checkout. Alternatively, supply its location with `--bundle`.
No Mac is needed during retrieval once the helpers are built.

In GitHub Actions, run the **Build device helpers** workflow on `main`. Download
the `fairplay-device-helpers-arm64` artifact when it finishes, unzip it, then
extract the included archive from the project root:

```sh
shasum -a 256 -c fairplay-device-helpers-arm64.tar.gz.sha256
mkdir -p credential-retrieval/build
tar -xzf fairplay-device-helpers-arm64.tar.gz -C credential-retrieval/build
```

The archive preserves executable permissions and contains all five required
helper/data files. The build does not retrieve or upload any account credentials.

For example, retrieve the US App Store account credential into the region
store used by `decrypt.py --region us`:

```sh
python3 credential-retrieval/retrieve.py \
  --ssh-host iphone.your-tailnet.ts.net \
  --ssh-key /path/to/device-ssh-key \
  --ipa /path/to/us-account-app.ipa \
  --output-dir credentials/us/appstore
```

`--ssh-host` accepts a Tailscale IP, MagicDNS name, other reachable hostname,
or SSH configuration alias. Direct mode defaults to port 22; set `--ssh-port`
for another port. It never runs `idevice_id` or `iproxy`. The native helper
reads the device's FairPlay identifier on the device itself. Optionally supply
`--device-udid` to verify that the SSH endpoint is the expected device.

The SSH user defaults to `root`; `--ssh-user` can override it, but the session
must have the privileges required by the device helpers. Standard OpenSSH
configuration/agent keys work when `--ssh-key` is omitted.

For the bot's password-based SSH setup, use `sshpass` and name the existing
environment variable rather than putting a password in the command:

```sh
python3 credential-retrieval/retrieve.py \
  --ssh-host iphone.your-tailnet.ts.net \
  --ssh-password-env IPHONE_SSH_PASS \
  --ipa /path/to/us-account-app.ipa \
  --output-dir credentials/us/appstore
```

The named variable must be exported in the retriever's environment; `.env`
files are not loaded automatically. The password is passed to `sshpass` in
its environment, not in the command arguments. `--ssh-key` and
`--ssh-password-env` are mutually exclusive.

Use the device address already configured for the selected bot device and
the IPA/SINF acquired by the selected region's Apple Account. The region
directory does not select or switch the device's account. A matching installed
app is still required. Save an Arcade credential to `credentials/us/arcade`
instead. Output directories must be new, and the saved credential must be
exactly 16 bytes. Credential files are written with owner-only permissions.

Retrieval restarts `fairplayd` and may launch/stop the trigger app. Run it while
that device is idle. After extraction, the device can return to normal bot
work; the saved credential is used independently on the VPS.
