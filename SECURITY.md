# Security policy

QEV is security-sensitive software. Reports should be handled privately first.

## Reporting

Send reports to:

```text
bryanleonard@imagineqira.com
```

Include:

- affected package or app version
- operating system and Node version, if relevant
- exact command or flow used
- expected behavior
- observed behavior
- proof-of-concept vaults only if they do not contain private data

Do not include real secrets, private logs, production vault passphrases, or
personal documents.

## Scope

In scope:

- vaults opening with an incorrect passphrase
- undetected vault tampering
- plaintext or passphrase logging
- CLI argument handling that exposes passphrases
- malformed vault parsing issues
- package integrity or dependency concerns specific to QEV

Out of scope:

- weak user passphrases
- a compromised local machine
- lost passphrases
- phishing or social engineering
- issues in unrelated dependencies unless they directly affect QEV behavior

## Disclosure

Please allow a reasonable window for triage and fix preparation before public
disclosure.

## Supported versions

The actively supported npm package is:

```text
@bryan237l/qev-cli
```

Run this to check the installed CLI:

```sh
qev version
qev self-test
```
