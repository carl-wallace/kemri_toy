# kemri_toy

`kemri_toy` is a test utility for generating and processing [EnvelopedData](https://www.rfc-editor.org/rfc/rfc5652#section-6)
or [AuthEnvelopedData](https://www.rfc-editor.org/rfc/rfc5083#section-2.1) messages containing the 
[KEMRecipientInfo](https://datatracker.ietf.org/doc/html/draft-ietf-lamps-cms-kemri-07#section-3) structure defined in [RFC 9629](https://datatracker.ietf.org/doc/html/rfc9629). The tool is
primarily focused on use of the [ML-KEM algorithm](https://csrc.nist.gov/pubs/fips/203/ipd) and related [composite algorithms](https://datatracker.ietf.org/doc/html/draft-ietf-lamps-pq-composite-kem-12) in this context and was
produced as part of the [PQC certificates](https://github.com/IETF-Hackathon/pqc-certificates) hackathon project.

For convenience, the tool was expanded beyond its KEMRI purpose to include means of checking private key formats and 
generating and verifying [SignedData messages](https://datatracker.ietf.org/doc/html/draft-ietf-lamps-cms-composite-sigs-01) 
signed using [composite signature algorithms](https://datatracker.ietf.org/doc/html/draft-ietf-lamps-pq-composite-sigs-14).

```bash
Usage: kemri_toy [OPTIONS]

Options:
  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version

Common:
  -o, --output-folder <OUTPUT_FOLDER>
          Folder to which generated certificates, keys, EnvelopedData objects, and non-default decrypted payloads should be written

  -l, --logging-config <LOGGING_CONFIG>
          Full path and filename of YAML-formatted configuration file for log4rs logging mechanism. See https://docs.rs/log4rs/latest/log4rs/ for details

  -i, --input-file <INPUT_FILE>
          When encrypting, file that contains data to encrypt (abc is used when absent). When decrypting, file that contains DER-encoded EnvelopedData or AuthEnvelopedData object

Logging:
  -c, --log-to-console
          Log output to the console

Encryption:
      --kem <KEM>
          KEM algorithm to use when generating fresh keys, i.e., when encrypting and no ee_cert_file was provided
          
          [default: ml-kem512]
          [possible values: ml-kem512, ml-kem768, ml-kem1024, ml-kem768-rsa2048-sha3-256, ml-kem768-rsa3072-sha3-256, ml-kem768-rsa4096-sha3-256, ml-kem1024-rsa3072-sha3-256, ml-kem768-x25519-sha3-256, ml-kem768-ecdh-p256-sha3-256, ml-kem768-ecdh-p384-sha3-256, ml-kem1024-ecdh-p384-sha3-256, ml-kem1024-x448-sha3-256, ml-kem1024-ecdh-p521-sha3-256]

      --kdf <KDF>
          KDF algorithm to use when preparing an EnvelopedData or AuthEnvelopedData object
          
          [default: hkdf-sha256]
          [possible values: hkdf-sha256, hkdf-sha384, hkdf-sha512, kmac128, kmac256]

      --enc <ENC>
          Symmetric encryption algorithm to use when preparing an EnvelopedData object
          
          [default: aes128]
          [possible values: aes128, aes192, aes256]

      --aead <AEAD>
          AEAD encryption algorithm to use when preparing an AuthEnvelopedData object
          
          [default: aes128-gcm]
          [possible values: aes128-gcm, aes256-gcm]

  -a, --auth-env-data
          Generate AuthEnvelopedData instead of EnvelopedData (using --aead value, not --enc)

      --ee-cert-file <EE_CERT_FILE>
          File that contains a DER-encoded certificate containing public key to use to encrypt data

  -u, --ukm <UKM>
          String value to use as UserKeyingMaterial to provide context for the KDF

Decryption:
  -k, --ee-key-file <EE_KEY_FILE>
          File that contains a DER-encoded OneAsymmetricKey private key to use when decrypting data

Signing:
      --sig <SIG>
          Signature algorithm to use when preparing a certificate or SignedData object
          
          [default: ml-dsa44]
          [possible values: ml-dsa44, ml-dsa65, ml-dsa87, slh-dsa-sha2-128s, slh-dsa-sha2-128f, slh-dsa-sha2-192s, slh-dsa-sha2-192f, slh-dsa-sha2-256s, slh-dsa-sha2-256f, slh-dsa-shake128s, slh-dsa-shake128f, slh-dsa-shake192s, slh-dsa-shake192f, slh-dsa-shake256s, slh-dsa-shake256f, mldsa44-rsa2048-pss-sha256, mldsa44-rsa2048-pkcs15-sha256, mldsa44-ed25519-sha512, mldsa44-ecdsa-p256-sha256, mldsa65-rsa3072-pss-sha512, mldsa65-rsa4096-pss-sha512, mldsa65-rsa4096-pkcs15-sha512, mldsa65-ecdsa-p256-sha512, mldsa65-ecdsa-p384-sha512, mldsa65-ed25519-sha512, mldsa87-ecdsa-p384-sha512, mldsa87-ed448-shake256, mldsa87-rsa3072-pss-sha512, mldsa87-rsa4096-pss-sha512, mldsa87-ecdsa-p521-sha512]

      --generate-signed-data
          Also generate a SignedData when generating a fresh signature key pair

Certificate Generation:
      --pub-key-file <PUB_KEY_FILE>
          File that contains a DER-encoded OneAsymmetricKey private key to use when generating a certificate

  -g, --generate-cert
          Generate a certificate from a public key (so all the other stuff can work)

Verification:
      --check-private-key
          Perform consistency checks for a private key --input-file and public key from certificate from --ee-cert-file

  -v, --verify-signed-data
          Verify a SignedData from --input-file
 ```

## Encrypting
Encryption requires an end entity certificate. Running the tool with no `--ee-cert-file` parameter will cause generation
of a new TA certificate, a new end entity key pair, a new end entity certificate, and an EnvelopedData object encrypted
for the fresh end entity key pair containing "abc" as the encrypted payload (or the contents of `--input-file`). An 
existing key can be used by passing the `--ee-cert-file` parameter.

The `--kem` parameter can be provided (without `--ee-cert-file`) to generate different types of end entity keys and certificates.

The `--kdf` parameter can be provided to cause usage of various KDF algorithms when generating `EnvelopedData` or `AuthEnvelopedData` objects.

The `--enc` parameter can be provided to cause usage of various symmetric encryption algorithms when generating `EnvelopedData` objects.

The `--aead` parameter can be provided to cause usage of various AEAD encryption algorithms when generating `AuthEnvelopedData` objects.

The `--ukm` parameter can be provided to provide a value for the optional `UserKeyingMaterial` field.

The `--auth-env-data` parameter can be used to cause generation of `AuthEnvelopedData` objects instead of `EnvelopedData` objects.

The `--input-file` parameter can be used to provide alternative data for the encrypted payload.

Files are written to the location specified by the `--output-folder` parameter or the current directory.
Key and certificate files are written using file names indicating the KEM algorithm. `EnvelopedData` and `AuthEnvelopedData` files
are written using a name indicating the content type, KDF, KEM and UKM state.

## Decrypting
Decryption requires the `--input-file` parameter (which should reference a suitable DER-encoded `EnvelopedData` or `AuthEnvelopedData` object) and the
`--ee-key-file` parameter (which should reference the key to decrypt the `EnvelopedData` or `AuthEnvelopedData` object as a DER-encoded `OneAsymmetricKey`).

If the decrypted data is not the default (abc), then it will be written to the location specified by the `--output-folder` parameter or the current directory
with a name based on the input filename.