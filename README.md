# ForgeMint

A Simple Forge of KeyStore

## Configuration

Work dir: `/data/adb/forgemint/` — created on install. All files hot-reloaded on change.

### 1. target.txt — Package modes

```
<package>!     Generate mode — full software key + certificate chain
<package>?     Patch mode — hardware key + certificate replacement
<package>      Auto mode — TEE alive → Patch, TEE dead → Generate
```

Blank lines and `#` comments ignored. First matching package wins.

Set `whitelist_mode=true` in `config` to invert: listed packages are excluded, everything else is intercepted.

### 2. keybox.xml — Attestation chain

```xml
<?xml version="1.0"?>
<AndroidAttestation>
    <NumberOfKeyboxes>1</NumberOfKeyboxes>
    <Keybox DeviceID="...">
        <Key algorithm="ecdsa|rsa">
            <PrivateKey format="pem">
-----BEGIN EC PRIVATE KEY-----
...
-----END EC PRIVATE KEY-----
            </PrivateKey>
            <CertificateChain>
                <NumberOfCertificates>...</NumberOfCertificates>
                    <Certificate format="pem">
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
                    </Certificate>
                ... more certificates
            </CertificateChain>
        </Key>
    </Keybox>
</AndroidAttestation>
```

At least one EC and one RSA key recommended. Expired certificates trigger CRL detection.

### 3. security_patch.txt — Custom patch levels

```
system=20260601
vendor=20260601
boot=20260601
all=20260601
```

`YYYYMMDD` or `YYYYMM`. `=prop` reads the live system property. `all` sets all three.

### 4. config — Runtime flags

```
debug=false
verbose_log=false
fallback=true
whitelist_mode=false
```

| Key | `false` | `true` |
|-----|---------|--------|
| `debug` | kmsg (invisible to logcat) | logcat |
| `verbose_log` | warnings + errors only | all levels |
| `fallback` | keybox empty → hardware | keybox empty → self-signed |
| `whitelist_mode` | target.txt = whitelist | target.txt = blacklist |

## License

GPL-2.0-or-later. See [LICENSE](LICENSE).
