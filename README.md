# kemri_toy

`kemri_toy` is a test utility for generating and processing [EnvelopedData](https://www.rfc-editor.org/rfc/rfc5652#section-6)
or [AuthEnvelopedData](https://www.rfc-editor.org/rfc/rfc5083#section-2.1) messages containing the new
[KEMRecipientInfo](https://datatracker.ietf.org/doc/html/draft-ietf-lamps-cms-kemri-07#section-3) structure. The tool is
primarily focused on use of the [ML-KEM algorithm](https://csrc.nist.gov/pubs/fips/203/ipd) in this context and was
produced as part of the [PQC certificates](https://github.com/IETF-Hackathon/pqc-certificates) hackathon project.

```bash
Usage: kemri_toy [OPTIONS]

Options:
  -h, --help     Print help (see more with '--help')
  -V, --version  Print version

Common:
  -o, --output-folder <OUTPUT_FOLDER>
          Folder to which generated certificates, keys, EnvelopedData objects, and non-default decrypted payloads should be written
  -l, --logging-config <LOGGING_CONFIG>
          Full path and filename of YAML-formatted configuration file for log4rs logging mechanism. See https://docs.rs/log4rs/latest/log4rs/ for details
  -i, --input-file <INPUT_FILE>
          When encrypting, file that contains data to encrypt (abc is used when absent). When decrypting, file that contains DER-encoded EnvelopedData or AuthEnvelopedData object

Encryption:
      --kem <KEM>                    KEM algorithm to use when generating fresh keys, i.e., when encrypting and no ee_cert_file was provided [default: ml-kem512] [possible values: ml-kem512, ml-kem768, ml-kem1024]
      --kdf <KDF>                    KDF algorithm to use when preparing an EnvelopedData or AuthEnvelopedData object [default: hkdf-sha256] [possible values: hkdf-sha256, hkdf-sha384, hkdf-sha512]
      --enc <ENC>                    Symmetric encryption algorithm to use when preparing an EnvelopedData object [default: aes128] [possible values: aes128, aes192, aes256]
      --aead <AEAD>                  AEAD encryption algorithm to use when preparing an AuthEnvelopedData object [default: aes128-gcm] [possible values: aes128-gcm, aes256-gcm]
  -a, --auth-env-data                Generate AuthEnvelopedData instead of EnvelopedData (using --aead value, not --enc)
  -c, --ee-cert-file <EE_CERT_FILE>  File that contains a DER-encoded certificate containing public key to use to encrypt data
  -u, --ukm <UKM>                    String value to use as UserKeyingMaterial to provide context for the KDF

Decryption:
  -k, --ee-key-file <EE_KEY_FILE>  File that contains a DER-encoded OneAsymmetricKey private key to use when decrypting data
 ```

## Encrypting
Encryption requires an end entity certificate. Running the tool with no `--ee-cert-file` parameter will cause generation
of a new TA certificate, a new end entity key pair, a new end entity certificate, and an EnvelopedData object encrypted
for the fresh end entity key pair containing "abc" as the encrypted payload. An existing key can be used by passing
the `--ee-cert-file` parameter.

The `--kem` parameter can be provided (without `--ee-cert-file`) to generate different types of end entity keys and certificates.

The `--kdf` parameter can be provided to cause usage of alternative KDF algorithms.

The `--enc` parameter can be provided to cause usage of alternative symmetric encryption algorithms when generating `EnvelopedData` objects.

The `--aead` parameter can be provided to cause usage of alternative AEAD encryption algorithms when generating `AuthEnvelopedData` objects.

The `--ukm` parameter can be provided to provide a value for the optional `UserKeyingMaterial` field.

The `--auth-env-data` parameter can be used to cause generation of `AuthEnvelopedData` objects instead of `EnvelopedData` objects.

The `--input-file` parameter can be used to provide alternative data for the encrypted payload.

Files are written to the location specified by the --output-folder parameter or the current directory.
Key and certificate files are written using file names indicating the KEM algorithm. `EnvelopedData` and `AuthEnvelopedData` files
are written using a name indicating the content type, KDF, KEM and UKM state.

## Decrypting
Decryption requires the `--input-file` parameter (which should reference a suitable DER-encoded `EnvelopedData` or `AuthEnvelopedData` object) and the
`--ee-key-file` parameter (which should reference the key to decrypt the `EnvelopedData` or `AuthEnvelopedData` object as a DER-encoded `OneAsymmetricKey`).

If the decrypted data is not the default (abc), then it will be written to the location specified by the `--output-folder` parameter or the current directory
with a name based on the input filename.