rmdir -r output
mkdir output

echo "generating EnvelopedData"
./kemri_toy -o output
./kemri_toy -o output --kem ml-kem768
./kemri_toy -o output --kem ml-kem1024
./kemri_toy -o output --kem ml-kem768-rsa2048-sha3-256
./kemri_toy -o output --kem ml-kem768-rsa3072-sha3-256
./kemri_toy -o output --kem ml-kem768-rsa4096-sha3-256
./kemri_toy -o output --kem ml-kem1024-rsa3072-sha3-256
./kemri_toy -o output --kem ml-kem768-ecdh-p256-sha3-256
./kemri_toy -o output --kem ml-kem768-ecdh-p384-sha3-256
./kemri_toy -o output --kem ml-kem1024-ecdh-p384-sha3-256
./kemri_toy -o output --kem ml-kem1024-ecdh-p521-sha3-256

echo "processing EnvelopedData"
./kemri_toy -i ./output/mlkem512-2.16.840.1.101.3.4.4.1_kemri_id-alg-hkdf-with-sha256.der -k ./output/mlkem512-2.16.840.1.101.3.4.4.1_expandedkey_priv.der
./kemri_toy -i ./output/mlkem768-2.16.840.1.101.3.4.4.2_kemri_id-alg-hkdf-with-sha256.der -k ./output/mlkem768-2.16.840.1.101.3.4.4.2_expandedkey_priv.der
./kemri_toy -i ./output/mlkem1024-2.16.840.1.101.3.4.4.3_kemri_id-alg-hkdf-with-sha256.der -k ./output/mlkem1024-2.16.840.1.101.3.4.4.3_expandedkey_priv.der
./kemri_toy -i ./output/mlkem512-2.16.840.1.101.3.4.4.1_kemri_id-alg-hkdf-with-sha256.der -k ./output/mlkem512-2.16.840.1.101.3.4.4.1_seed_priv.der
./kemri_toy -i ./output/mlkem768-2.16.840.1.101.3.4.4.2_kemri_id-alg-hkdf-with-sha256.der -k ./output/mlkem768-2.16.840.1.101.3.4.4.2_seed_priv.der
./kemri_toy -i ./output/mlkem1024-2.16.840.1.101.3.4.4.3_kemri_id-alg-hkdf-with-sha256.der -k ./output/mlkem1024-2.16.840.1.101.3.4.4.3_seed_priv.der
./kemri_toy -i ./output/mlkem512-2.16.840.1.101.3.4.4.1_kemri_id-alg-hkdf-with-sha256.der -k ./output/mlkem512-2.16.840.1.101.3.4.4.1_both_priv.der
./kemri_toy -i ./output/mlkem768-2.16.840.1.101.3.4.4.2_kemri_id-alg-hkdf-with-sha256.der -k ./output/mlkem768-2.16.840.1.101.3.4.4.2_both_priv.der
./kemri_toy -i ./output/mlkem1024-2.16.840.1.101.3.4.4.3_kemri_id-alg-hkdf-with-sha256.der -k ./output/mlkem1024-2.16.840.1.101.3.4.4.3_both_priv.der
./kemri_toy -i ./output/id-MLKEM768-RSA2048-SHA3-256-1.3.6.1.5.5.7.6.55_kemri_id-alg-hkdf-with-sha256.der -k ./output/id-MLKEM768-RSA2048-SHA3-256-1.3.6.1.5.5.7.6.55_priv.der
./kemri_toy -i ./output/id-MLKEM768-RSA3072-SHA3-256-1.3.6.1.5.5.7.6.56_kemri_id-alg-hkdf-with-sha256.der -k ./output/id-MLKEM768-RSA3072-SHA3-256-1.3.6.1.5.5.7.6.56_priv.der
./kemri_toy -i ./output/id-MLKEM768-RSA4096-SHA3-256-1.3.6.1.5.5.7.6.57_kemri_id-alg-hkdf-with-sha256.der -k ./output/id-MLKEM768-RSA4096-SHA3-256-1.3.6.1.5.5.7.6.57_priv.der
./kemri_toy -i ./output/id-MLKEM768-ECDH-P256-SHA3-256-1.3.6.1.5.5.7.6.59_kemri_id-alg-hkdf-with-sha256.der -k ./output/id-MLKEM768-ECDH-P256-SHA3-256-1.3.6.1.5.5.7.6.59_priv.der
./kemri_toy -i ./output/id-MLKEM768-ECDH-P384-SHA3-256-1.3.6.1.5.5.7.6.60_kemri_id-alg-hkdf-with-sha256.der -k ./output/id-MLKEM768-ECDH-P384-SHA3-256-1.3.6.1.5.5.7.6.60_priv.der
./kemri_toy -i ./output/id-MLKEM1024-RSA3072-SHA3-256-1.3.6.1.5.5.7.6.62_kemri_id-alg-hkdf-with-sha256.der -k ./output/id-MLKEM1024-RSA3072-SHA3-256-1.3.6.1.5.5.7.6.62_priv.der
./kemri_toy -i ./output/id-MLKEM1024-ECDH-P384-SHA3-256-1.3.6.1.5.5.7.6.63_kemri_id-alg-hkdf-with-sha256.der -k ./output/id-MLKEM1024-ECDH-P384-SHA3-256-1.3.6.1.5.5.7.6.63_priv.der
./kemri_toy -i ./output/id-MLKEM1024-ECDH-P521-SHA3-256-1.3.6.1.5.5.7.6.66_kemri_id-alg-hkdf-with-sha256.der -k ./output/id-MLKEM1024-ECDH-P521-SHA3-256-1.3.6.1.5.5.7.6.66_priv.der

echo "generating EnvelopedData with UKM"
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/mlkem512-2.16.840.1.101.3.4.4.1_ee.der
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/mlkem768-2.16.840.1.101.3.4.4.2_ee.der
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/mlkem1024-2.16.840.1.101.3.4.4.3_ee.der
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/id-MLKEM768-RSA2048-SHA3-256-1.3.6.1.5.5.7.6.55_ee.der
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/id-MLKEM768-RSA3072-SHA3-256-1.3.6.1.5.5.7.6.56_ee.der
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/id-MLKEM768-RSA4096-SHA3-256-1.3.6.1.5.5.7.6.57_ee.der
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/id-MLKEM768-ECDH-P256-SHA3-256-1.3.6.1.5.5.7.6.59_ee.der
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/id-MLKEM768-ECDH-P384-SHA3-256-1.3.6.1.5.5.7.6.60_ee.der
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/id-MLKEM1024-RSA3072-SHA3-256-1.3.6.1.5.5.7.6.62_ee.der
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/id-MLKEM1024-ECDH-P384-SHA3-256-1.3.6.1.5.5.7.6.63_ee.der
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/id-MLKEM1024-ECDH-P521-SHA3-256-1.3.6.1.5.5.7.6.66_ee.der

echo "processing EnvelopedData with UKM"
./kemri_toy -i ./output/mlkem512-2.16.840.1.101.3.4.4.1_kemri_id-alg-hkdf-with-sha256_ukm.der -k ./output/mlkem512-2.16.840.1.101.3.4.4.1_expandedkey_priv.der
./kemri_toy -i ./output/mlkem768-2.16.840.1.101.3.4.4.2_kemri_id-alg-hkdf-with-sha256_ukm.der -k ./output/mlkem768-2.16.840.1.101.3.4.4.2_expandedkey_priv.der
./kemri_toy -i ./output/mlkem1024-2.16.840.1.101.3.4.4.3_kemri_id-alg-hkdf-with-sha256_ukm.der -k ./output/mlkem1024-2.16.840.1.101.3.4.4.3_expandedkey_priv.der
./kemri_toy -i ./output/mlkem512-2.16.840.1.101.3.4.4.1_kemri_id-alg-hkdf-with-sha256_ukm.der -k ./output/mlkem512-2.16.840.1.101.3.4.4.1_seed_priv.der
./kemri_toy -i ./output/mlkem768-2.16.840.1.101.3.4.4.2_kemri_id-alg-hkdf-with-sha256_ukm.der -k ./output/mlkem768-2.16.840.1.101.3.4.4.2_seed_priv.der
./kemri_toy -i ./output/mlkem1024-2.16.840.1.101.3.4.4.3_kemri_id-alg-hkdf-with-sha256_ukm.der -k ./output/mlkem1024-2.16.840.1.101.3.4.4.3_seed_priv.der
./kemri_toy -i ./output/mlkem512-2.16.840.1.101.3.4.4.1_kemri_id-alg-hkdf-with-sha256_ukm.der -k ./output/mlkem512-2.16.840.1.101.3.4.4.1_both_priv.der
./kemri_toy -i ./output/mlkem768-2.16.840.1.101.3.4.4.2_kemri_id-alg-hkdf-with-sha256_ukm.der -k ./output/mlkem768-2.16.840.1.101.3.4.4.2_both_priv.der
./kemri_toy -i ./output/mlkem1024-2.16.840.1.101.3.4.4.3_kemri_id-alg-hkdf-with-sha256_ukm.der -k ./output/mlkem1024-2.16.840.1.101.3.4.4.3_both_priv.der
./kemri_toy -i ./output/id-MLKEM768-RSA2048-SHA3-256-1.3.6.1.5.5.7.6.55_kemri_id-alg-hkdf-with-sha256_ukm.der -k ./output/id-MLKEM768-RSA2048-SHA3-256-1.3.6.1.5.5.7.6.55_priv.der
./kemri_toy -i ./output/id-MLKEM768-RSA3072-SHA3-256-1.3.6.1.5.5.7.6.56_kemri_id-alg-hkdf-with-sha256_ukm.der -k ./output/id-MLKEM768-RSA3072-SHA3-256-1.3.6.1.5.5.7.6.56_priv.der
./kemri_toy -i ./output/id-MLKEM768-RSA4096-SHA3-256-1.3.6.1.5.5.7.6.57_kemri_id-alg-hkdf-with-sha256_ukm.der -k ./output/id-MLKEM768-RSA4096-SHA3-256-1.3.6.1.5.5.7.6.57_priv.der
./kemri_toy -i ./output/id-MLKEM768-ECDH-P256-SHA3-256-1.3.6.1.5.5.7.6.59_kemri_id-alg-hkdf-with-sha256_ukm.der -k ./output/id-MLKEM768-ECDH-P256-SHA3-256-1.3.6.1.5.5.7.6.59_priv.der
./kemri_toy -i ./output/id-MLKEM768-ECDH-P384-SHA3-256-1.3.6.1.5.5.7.6.60_kemri_id-alg-hkdf-with-sha256_ukm.der -k ./output/id-MLKEM768-ECDH-P384-SHA3-256-1.3.6.1.5.5.7.6.60_priv.der
./kemri_toy -i ./output/id-MLKEM1024-RSA3072-SHA3-256-1.3.6.1.5.5.7.6.62_kemri_id-alg-hkdf-with-sha256_ukm.der -k ./output/id-MLKEM1024-RSA3072-SHA3-256-1.3.6.1.5.5.7.6.62_priv.der
./kemri_toy -i ./output/id-MLKEM1024-ECDH-P384-SHA3-256-1.3.6.1.5.5.7.6.63_kemri_id-alg-hkdf-with-sha256_ukm.der -k ./output/id-MLKEM1024-ECDH-P384-SHA3-256-1.3.6.1.5.5.7.6.63_priv.der
./kemri_toy -i ./output/id-MLKEM1024-ECDH-P521-SHA3-256-1.3.6.1.5.5.7.6.66_kemri_id-alg-hkdf-with-sha256_ukm.der -k ./output/id-MLKEM1024-ECDH-P521-SHA3-256-1.3.6.1.5.5.7.6.66_priv.der

echo "generating AuthEnvelopedData"
./kemri_toy -o output --aead aes256-gcm --auth-env-data -c ./output/mlkem512-2.16.840.1.101.3.4.4.1_ee.der
./kemri_toy -o output --aead aes256-gcm --auth-env-data -c ./output/mlkem768-2.16.840.1.101.3.4.4.2_ee.der
./kemri_toy -o output --aead aes256-gcm --auth-env-data -c ./output/mlkem1024-2.16.840.1.101.3.4.4.3_ee.der
./kemri_toy -o output --aead aes256-gcm --auth-env-data -c ./output/id-MLKEM768-RSA2048-SHA3-256-1.3.6.1.5.5.7.6.55_ee.der
./kemri_toy -o output --aead aes256-gcm --auth-env-data -c ./output/id-MLKEM768-RSA3072-SHA3-256-1.3.6.1.5.5.7.6.56_ee.der
./kemri_toy -o output --aead aes256-gcm --auth-env-data -c ./output/id-MLKEM768-RSA4096-SHA3-256-1.3.6.1.5.5.7.6.57_ee.der
./kemri_toy -o output --aead aes256-gcm --auth-env-data -c ./output/id-MLKEM768-ECDH-P256-SHA3-256-1.3.6.1.5.5.7.6.59_ee.der
./kemri_toy -o output --aead aes256-gcm --auth-env-data -c ./output/id-MLKEM768-ECDH-P384-SHA3-256-1.3.6.1.5.5.7.6.60_ee.der
./kemri_toy -o output --aead aes256-gcm --auth-env-data -c ./output/id-MLKEM1024-RSA3072-SHA3-256-1.3.6.1.5.5.7.6.62_ee.der
./kemri_toy -o output --aead aes256-gcm --auth-env-data -c ./output/id-MLKEM1024-ECDH-P384-SHA3-256-1.3.6.1.5.5.7.6.63_ee.der
./kemri_toy -o output --aead aes256-gcm --auth-env-data -c ./output/id-MLKEM1024-ECDH-P521-SHA3-256-1.3.6.1.5.5.7.6.66_ee.der

echo "processing AuthEnvelopedData"
./kemri_toy -i ./output/mlkem512-2.16.840.1.101.3.4.4.1_kemri_auth_id-alg-hkdf-with-sha256.der -k ./output/mlkem512-2.16.840.1.101.3.4.4.1_expandedkey_priv.der
./kemri_toy -i ./output/mlkem768-2.16.840.1.101.3.4.4.2_kemri_auth_id-alg-hkdf-with-sha256.der -k ./output/mlkem768-2.16.840.1.101.3.4.4.2_expandedkey_priv.der
./kemri_toy -i ./output/mlkem1024-2.16.840.1.101.3.4.4.3_kemri_auth_id-alg-hkdf-with-sha256.der -k ./output/mlkem1024-2.16.840.1.101.3.4.4.3_expandedkey_priv.der
./kemri_toy -i ./output/mlkem512-2.16.840.1.101.3.4.4.1_kemri_auth_id-alg-hkdf-with-sha256.der -k ./output/mlkem512-2.16.840.1.101.3.4.4.1_seed_priv.der
./kemri_toy -i ./output/mlkem768-2.16.840.1.101.3.4.4.2_kemri_auth_id-alg-hkdf-with-sha256.der -k ./output/mlkem768-2.16.840.1.101.3.4.4.2_seed_priv.der
./kemri_toy -i ./output/mlkem1024-2.16.840.1.101.3.4.4.3_kemri_auth_id-alg-hkdf-with-sha256.der -k ./output/mlkem1024-2.16.840.1.101.3.4.4.3_seed_priv.der
./kemri_toy -i ./output/mlkem512-2.16.840.1.101.3.4.4.1_kemri_auth_id-alg-hkdf-with-sha256.der -k ./output/mlkem512-2.16.840.1.101.3.4.4.1_both_priv.der
./kemri_toy -i ./output/mlkem768-2.16.840.1.101.3.4.4.2_kemri_auth_id-alg-hkdf-with-sha256.der -k ./output/mlkem768-2.16.840.1.101.3.4.4.2_both_priv.der
./kemri_toy -i ./output/mlkem1024-2.16.840.1.101.3.4.4.3_kemri_auth_id-alg-hkdf-with-sha256.der -k ./output/mlkem1024-2.16.840.1.101.3.4.4.3_both_priv.der
./kemri_toy -i ./output/id-MLKEM768-RSA2048-SHA3-256-1.3.6.1.5.5.7.6.55_kemri_auth_id-alg-hkdf-with-sha256.der -k ./output/id-MLKEM768-RSA2048-SHA3-256-1.3.6.1.5.5.7.6.55_priv.der
./kemri_toy -i ./output/id-MLKEM768-RSA3072-SHA3-256-1.3.6.1.5.5.7.6.56_kemri_auth_id-alg-hkdf-with-sha256.der -k ./output/id-MLKEM768-RSA3072-SHA3-256-1.3.6.1.5.5.7.6.56_priv.der
./kemri_toy -i ./output/id-MLKEM768-RSA4096-SHA3-256-1.3.6.1.5.5.7.6.57_kemri_auth_id-alg-hkdf-with-sha256.der -k ./output/id-MLKEM768-RSA4096-SHA3-256-1.3.6.1.5.5.7.6.57_priv.der
./kemri_toy -i ./output/id-MLKEM768-ECDH-P256-SHA3-256-1.3.6.1.5.5.7.6.59_kemri_auth_id-alg-hkdf-with-sha256.der -k ./output/id-MLKEM768-ECDH-P256-SHA3-256-1.3.6.1.5.5.7.6.59_priv.der
./kemri_toy -i ./output/id-MLKEM768-ECDH-P384-SHA3-256-1.3.6.1.5.5.7.6.60_kemri_auth_id-alg-hkdf-with-sha256.der -k ./output/id-MLKEM768-ECDH-P384-SHA3-256-1.3.6.1.5.5.7.6.60_priv.der
./kemri_toy -i ./output/id-MLKEM1024-RSA3072-SHA3-256-1.3.6.1.5.5.7.6.62_kemri_auth_id-alg-hkdf-with-sha256.der -k ./output/id-MLKEM1024-RSA3072-SHA3-256-1.3.6.1.5.5.7.6.62_priv.der
./kemri_toy -i ./output/id-MLKEM1024-ECDH-P384-SHA3-256-1.3.6.1.5.5.7.6.63_kemri_auth_id-alg-hkdf-with-sha256.der -k ./output/id-MLKEM1024-ECDH-P384-SHA3-256-1.3.6.1.5.5.7.6.63_priv.der
./kemri_toy -i ./output/id-MLKEM1024-ECDH-P521-SHA3-256-1.3.6.1.5.5.7.6.66_kemri_auth_id-alg-hkdf-with-sha256.der -k ./output/id-MLKEM1024-ECDH-P521-SHA3-256-1.3.6.1.5.5.7.6.66_priv.der

echo "generating AuthEnvelopedData with UKM"
./kemri_toy -o output -u "This is some User Keying Material" --aead aes256-gcm --auth-env-data -c ./output/mlkem512-2.16.840.1.101.3.4.4.1_ee.der
./kemri_toy -o output -u "This is some User Keying Material" --aead aes256-gcm --auth-env-data -c ./output/mlkem768-2.16.840.1.101.3.4.4.2_ee.der
./kemri_toy -o output -u "This is some User Keying Material" --aead aes256-gcm --auth-env-data -c ./output/mlkem1024-2.16.840.1.101.3.4.4.3_ee.der
./kemri_toy -o output -u "This is some User Keying Material" --aead aes256-gcm --auth-env-data -c ./output/id-MLKEM768-RSA2048-SHA3-256-1.3.6.1.5.5.7.6.55_ee.der
./kemri_toy -o output -u "This is some User Keying Material" --aead aes256-gcm --auth-env-data -c ./output/id-MLKEM768-RSA3072-SHA3-256-1.3.6.1.5.5.7.6.56_ee.der
./kemri_toy -o output -u "This is some User Keying Material" --aead aes256-gcm --auth-env-data -c ./output/id-MLKEM768-RSA4096-SHA3-256-1.3.6.1.5.5.7.6.57_ee.der
./kemri_toy -o output -u "This is some User Keying Material" --aead aes256-gcm --auth-env-data -c ./output/id-MLKEM1024-RSA3072-SHA3-256-1.3.6.1.5.5.7.6.62_ee.der
./kemri_toy -o output -u "This is some User Keying Material" --aead aes256-gcm --auth-env-data -c ./output/id-MLKEM768-ECDH-P256-SHA3-256-1.3.6.1.5.5.7.6.59_ee.der
./kemri_toy -o output -u "This is some User Keying Material" --aead aes256-gcm --auth-env-data -c ./output/id-MLKEM768-ECDH-P384-SHA3-256-1.3.6.1.5.5.7.6.60_ee.der
./kemri_toy -o output -u "This is some User Keying Material" --aead aes256-gcm --auth-env-data -c ./output/id-MLKEM1024-ECDH-P384-SHA3-256-1.3.6.1.5.5.7.6.63_ee.der
./kemri_toy -o output -u "This is some User Keying Material" --aead aes256-gcm --auth-env-data -c ./output/id-MLKEM1024-ECDH-P521-SHA3-256-1.3.6.1.5.5.7.6.66_ee.der

echo "processing AuthEnvelopedData with UKM"
./kemri_toy -i ./output/mlkem512-2.16.840.1.101.3.4.4.1_kemri_auth_id-alg-hkdf-with-sha256_ukm.der -k ./output/mlkem512-2.16.840.1.101.3.4.4.1_expandedkey_priv.der
./kemri_toy -i ./output/mlkem768-2.16.840.1.101.3.4.4.2_kemri_auth_id-alg-hkdf-with-sha256_ukm.der -k ./output/mlkem768-2.16.840.1.101.3.4.4.2_expandedkey_priv.der
./kemri_toy -i ./output/mlkem1024-2.16.840.1.101.3.4.4.3_kemri_auth_id-alg-hkdf-with-sha256_ukm.der -k ./output/mlkem1024-2.16.840.1.101.3.4.4.3_expandedkey_priv.der
./kemri_toy -i ./output/mlkem512-2.16.840.1.101.3.4.4.1_kemri_auth_id-alg-hkdf-with-sha256_ukm.der -k ./output/mlkem512-2.16.840.1.101.3.4.4.1_seed_priv.der
./kemri_toy -i ./output/mlkem768-2.16.840.1.101.3.4.4.2_kemri_auth_id-alg-hkdf-with-sha256_ukm.der -k ./output/mlkem768-2.16.840.1.101.3.4.4.2_seed_priv.der
./kemri_toy -i ./output/mlkem1024-2.16.840.1.101.3.4.4.3_kemri_auth_id-alg-hkdf-with-sha256_ukm.der -k ./output/mlkem1024-2.16.840.1.101.3.4.4.3_seed_priv.der
./kemri_toy -i ./output/mlkem512-2.16.840.1.101.3.4.4.1_kemri_auth_id-alg-hkdf-with-sha256_ukm.der -k ./output/mlkem512-2.16.840.1.101.3.4.4.1_both_priv.der
./kemri_toy -i ./output/mlkem768-2.16.840.1.101.3.4.4.2_kemri_auth_id-alg-hkdf-with-sha256_ukm.der -k ./output/mlkem768-2.16.840.1.101.3.4.4.2_both_priv.der
./kemri_toy -i ./output/mlkem1024-2.16.840.1.101.3.4.4.3_kemri_auth_id-alg-hkdf-with-sha256_ukm.der -k ./output/mlkem1024-2.16.840.1.101.3.4.4.3_both_priv.der
./kemri_toy -i ./output/id-MLKEM768-RSA2048-SHA3-256-1.3.6.1.5.5.7.6.55_kemri_auth_id-alg-hkdf-with-sha256_ukm.der -k ./output/id-MLKEM768-RSA2048-SHA3-256-1.3.6.1.5.5.7.6.55_priv.der
./kemri_toy -i ./output/id-MLKEM768-RSA3072-SHA3-256-1.3.6.1.5.5.7.6.56_kemri_auth_id-alg-hkdf-with-sha256_ukm.der -k ./output/id-MLKEM768-RSA3072-SHA3-256-1.3.6.1.5.5.7.6.56_priv.der
./kemri_toy -i ./output/id-MLKEM768-RSA4096-SHA3-256-1.3.6.1.5.5.7.6.57_kemri_auth_id-alg-hkdf-with-sha256_ukm.der -k ./output/id-MLKEM768-RSA4096-SHA3-256-1.3.6.1.5.5.7.6.57_priv.der
./kemri_toy -i ./output/id-MLKEM768-ECDH-P256-SHA3-256-1.3.6.1.5.5.7.6.59_kemri_auth_id-alg-hkdf-with-sha256_ukm.der -k ./output/id-MLKEM768-ECDH-P256-SHA3-256-1.3.6.1.5.5.7.6.59_priv.der
./kemri_toy -i ./output/id-MLKEM768-ECDH-P384-SHA3-256-1.3.6.1.5.5.7.6.60_kemri_auth_id-alg-hkdf-with-sha256_ukm.der -k ./output/id-MLKEM768-ECDH-P384-SHA3-256-1.3.6.1.5.5.7.6.60_priv.der
./kemri_toy -i ./output/id-MLKEM1024-RSA3072-SHA3-256-1.3.6.1.5.5.7.6.62_kemri_auth_id-alg-hkdf-with-sha256_ukm.der -k ./output/id-MLKEM1024-RSA3072-SHA3-256-1.3.6.1.5.5.7.6.62_priv.der
./kemri_toy -i ./output/id-MLKEM1024-ECDH-P384-SHA3-256-1.3.6.1.5.5.7.6.63_kemri_auth_id-alg-hkdf-with-sha256_ukm.der -k ./output/id-MLKEM1024-ECDH-P384-SHA3-256-1.3.6.1.5.5.7.6.63_priv.der
./kemri_toy -i ./output/id-MLKEM1024-ECDH-P521-SHA3-256-1.3.6.1.5.5.7.6.66_kemri_auth_id-alg-hkdf-with-sha256_ukm.der -k ./output/id-MLKEM1024-ECDH-P521-SHA3-256-1.3.6.1.5.5.7.6.66_priv.der


