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
./kemri_toy -i ./output/id-MLKEM768-RSA2048-SHA3-256-2.16.840.1.114027.80.5.2.74_kemri_id-alg-hkdf-with-sha256.der -k ./output/id-MLKEM768-RSA2048-SHA3-256-2.16.840.1.114027.80.5.2.74_priv.der
./kemri_toy -i ./output/id-MLKEM768-RSA3072-SHA3-256-2.16.840.1.114027.80.5.2.75_kemri_id-alg-hkdf-with-sha256.der -k ./output/id-MLKEM768-RSA3072-SHA3-256-2.16.840.1.114027.80.5.2.75_priv.der
./kemri_toy -i ./output/id-MLKEM768-RSA4096-SHA3-256-2.16.840.1.114027.80.5.2.76_kemri_id-alg-hkdf-with-sha256.der -k ./output/id-MLKEM768-RSA4096-SHA3-256-2.16.840.1.114027.80.5.2.76_priv.der
./kemri_toy -i ./output/id-MLKEM768-ECDH-P256-SHA3-256-2.16.840.1.114027.80.5.2.78_kemri_id-alg-hkdf-with-sha256.der -k ./output/id-MLKEM768-ECDH-P256-SHA3-256-2.16.840.1.114027.80.5.2.78_priv.der
./kemri_toy -i ./output/id-MLKEM768-ECDH-P384-SHA3-256-2.16.840.1.114027.80.5.2.79_kemri_id-alg-hkdf-with-sha256.der -k ./output/id-MLKEM768-ECDH-P384-SHA3-256-2.16.840.1.114027.80.5.2.79_priv.der
./kemri_toy -i ./output/id-MLKEM1024-RSA3072-SHA3-256-2.16.840.1.114027.80.5.2.81_kemri_id-alg-hkdf-with-sha256.der -k ./output/id-MLKEM1024-RSA3072-SHA3-256-2.16.840.1.114027.80.5.2.81_priv.der
./kemri_toy -i ./output/id-MLKEM1024-ECDH-P384-SHA3-256-2.16.840.1.114027.80.5.2.82_kemri_id-alg-hkdf-with-sha256.der -k ./output/id-MLKEM1024-ECDH-P384-SHA3-256-2.16.840.1.114027.80.5.2.82_priv.der
./kemri_toy -i ./output/id-MLKEM1024-ECDH-P521-SHA3-256-2.16.840.1.114027.80.5.2.85_kemri_id-alg-hkdf-with-sha256.der -k ./output/id-MLKEM1024-ECDH-P521-SHA3-256-2.16.840.1.114027.80.5.2.85_priv.der

echo "generating EnvelopedData with UKM"
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/mlkem512-2.16.840.1.101.3.4.4.1_ee.der
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/mlkem768-2.16.840.1.101.3.4.4.2_ee.der
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/mlkem1024-2.16.840.1.101.3.4.4.3_ee.der
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/id-MLKEM768-RSA2048-SHA3-256-2.16.840.1.114027.80.5.2.74_ee.der
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/id-MLKEM768-RSA3072-SHA3-256-2.16.840.1.114027.80.5.2.75_ee.der
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/id-MLKEM768-RSA4096-SHA3-256-2.16.840.1.114027.80.5.2.76_ee.der
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/id-MLKEM768-ECDH-P256-SHA3-256-2.16.840.1.114027.80.5.2.78_ee.der
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/id-MLKEM768-ECDH-P384-SHA3-256-2.16.840.1.114027.80.5.2.79_ee.der
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/id-MLKEM1024-RSA3072-SHA3-256-2.16.840.1.114027.80.5.2.81_ee.der
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/id-MLKEM1024-ECDH-P384-SHA3-256-2.16.840.1.114027.80.5.2.82_ee.der
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/id-MLKEM1024-ECDH-P521-SHA3-256-2.16.840.1.114027.80.5.2.85_ee.der

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
./kemri_toy -i ./output/id-MLKEM768-RSA2048-SHA3-256-2.16.840.1.114027.80.5.2.74_kemri_id-alg-hkdf-with-sha256_ukm.der -k ./output/id-MLKEM768-RSA2048-SHA3-256-2.16.840.1.114027.80.5.2.74_priv.der
./kemri_toy -i ./output/id-MLKEM768-RSA3072-SHA3-256-2.16.840.1.114027.80.5.2.75_kemri_id-alg-hkdf-with-sha256_ukm.der -k ./output/id-MLKEM768-RSA3072-SHA3-256-2.16.840.1.114027.80.5.2.75_priv.der
./kemri_toy -i ./output/id-MLKEM768-RSA4096-SHA3-256-2.16.840.1.114027.80.5.2.76_kemri_id-alg-hkdf-with-sha256_ukm.der -k ./output/id-MLKEM768-RSA4096-SHA3-256-2.16.840.1.114027.80.5.2.76_priv.der
./kemri_toy -i ./output/id-MLKEM768-ECDH-P256-SHA3-256-2.16.840.1.114027.80.5.2.78_kemri_id-alg-hkdf-with-sha256_ukm.der -k ./output/id-MLKEM768-ECDH-P256-SHA3-256-2.16.840.1.114027.80.5.2.78_priv.der
./kemri_toy -i ./output/id-MLKEM768-ECDH-P384-SHA3-256-2.16.840.1.114027.80.5.2.79_kemri_id-alg-hkdf-with-sha256_ukm.der -k ./output/id-MLKEM768-ECDH-P384-SHA3-256-2.16.840.1.114027.80.5.2.79_priv.der
./kemri_toy -i ./output/id-MLKEM1024-RSA3072-SHA3-256-2.16.840.1.114027.80.5.2.81_kemri_id-alg-hkdf-with-sha256_ukm.der -k ./output/id-MLKEM1024-RSA3072-SHA3-256-2.16.840.1.114027.80.5.2.81_priv.der
./kemri_toy -i ./output/id-MLKEM1024-ECDH-P384-SHA3-256-2.16.840.1.114027.80.5.2.82_kemri_id-alg-hkdf-with-sha256_ukm.der -k ./output/id-MLKEM1024-ECDH-P384-SHA3-256-2.16.840.1.114027.80.5.2.82_priv.der
./kemri_toy -i ./output/id-MLKEM1024-ECDH-P521-SHA3-256-2.16.840.1.114027.80.5.2.85_kemri_id-alg-hkdf-with-sha256_ukm.der -k ./output/id-MLKEM1024-ECDH-P521-SHA3-256-2.16.840.1.114027.80.5.2.85_priv.der

echo "generating AuthEnvelopedData"
./kemri_toy -o output --aead aes256-gcm --auth-env-data -c ./output/mlkem512-2.16.840.1.101.3.4.4.1_ee.der
./kemri_toy -o output --aead aes256-gcm --auth-env-data -c ./output/mlkem768-2.16.840.1.101.3.4.4.2_ee.der
./kemri_toy -o output --aead aes256-gcm --auth-env-data -c ./output/mlkem1024-2.16.840.1.101.3.4.4.3_ee.der
./kemri_toy -o output --aead aes256-gcm --auth-env-data -c ./output/id-MLKEM768-RSA2048-SHA3-256-2.16.840.1.114027.80.5.2.74_ee.der
./kemri_toy -o output --aead aes256-gcm --auth-env-data -c ./output/id-MLKEM768-RSA3072-SHA3-256-2.16.840.1.114027.80.5.2.75_ee.der
./kemri_toy -o output --aead aes256-gcm --auth-env-data -c ./output/id-MLKEM768-RSA4096-SHA3-256-2.16.840.1.114027.80.5.2.76_ee.der
./kemri_toy -o output --aead aes256-gcm --auth-env-data -c ./output/id-MLKEM768-ECDH-P256-SHA3-256-2.16.840.1.114027.80.5.2.78_ee.der
./kemri_toy -o output --aead aes256-gcm --auth-env-data -c ./output/id-MLKEM768-ECDH-P384-SHA3-256-2.16.840.1.114027.80.5.2.79_ee.der
./kemri_toy -o output --aead aes256-gcm --auth-env-data -c ./output/id-MLKEM1024-RSA3072-SHA3-256-2.16.840.1.114027.80.5.2.81_ee.der
./kemri_toy -o output --aead aes256-gcm --auth-env-data -c ./output/id-MLKEM1024-ECDH-P384-SHA3-256-2.16.840.1.114027.80.5.2.82_ee.der
./kemri_toy -o output --aead aes256-gcm --auth-env-data -c ./output/id-MLKEM1024-ECDH-P521-SHA3-256-2.16.840.1.114027.80.5.2.85_ee.der

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
./kemri_toy -i ./output/id-MLKEM768-RSA2048-SHA3-256-2.16.840.1.114027.80.5.2.74_kemri_auth_id-alg-hkdf-with-sha256.der -k ./output/id-MLKEM768-RSA2048-SHA3-256-2.16.840.1.114027.80.5.2.74_priv.der
./kemri_toy -i ./output/id-MLKEM768-RSA3072-SHA3-256-2.16.840.1.114027.80.5.2.75_kemri_auth_id-alg-hkdf-with-sha256.der -k ./output/id-MLKEM768-RSA3072-SHA3-256-2.16.840.1.114027.80.5.2.75_priv.der
./kemri_toy -i ./output/id-MLKEM768-RSA4096-SHA3-256-2.16.840.1.114027.80.5.2.76_kemri_auth_id-alg-hkdf-with-sha256.der -k ./output/id-MLKEM768-RSA4096-SHA3-256-2.16.840.1.114027.80.5.2.76_priv.der
./kemri_toy -i ./output/id-MLKEM768-ECDH-P256-SHA3-256-2.16.840.1.114027.80.5.2.78_kemri_auth_id-alg-hkdf-with-sha256.der -k ./output/id-MLKEM768-ECDH-P256-SHA3-256-2.16.840.1.114027.80.5.2.78_priv.der
./kemri_toy -i ./output/id-MLKEM768-ECDH-P384-SHA3-256-2.16.840.1.114027.80.5.2.79_kemri_auth_id-alg-hkdf-with-sha256.der -k ./output/id-MLKEM768-ECDH-P384-SHA3-256-2.16.840.1.114027.80.5.2.79_priv.der
./kemri_toy -i ./output/id-MLKEM1024-RSA3072-SHA3-256-2.16.840.1.114027.80.5.2.81_kemri_auth_id-alg-hkdf-with-sha256.der -k ./output/id-MLKEM1024-RSA3072-SHA3-256-2.16.840.1.114027.80.5.2.81_priv.der
./kemri_toy -i ./output/id-MLKEM1024-ECDH-P384-SHA3-256-2.16.840.1.114027.80.5.2.82_kemri_auth_id-alg-hkdf-with-sha256.der -k ./output/id-MLKEM1024-ECDH-P384-SHA3-256-2.16.840.1.114027.80.5.2.82_priv.der
./kemri_toy -i ./output/id-MLKEM1024-ECDH-P521-SHA3-256-2.16.840.1.114027.80.5.2.85_kemri_auth_id-alg-hkdf-with-sha256.der -k ./output/id-MLKEM1024-ECDH-P521-SHA3-256-2.16.840.1.114027.80.5.2.85_priv.der

echo "generating AuthEnvelopedData with UKM"
./kemri_toy -o output -u "This is some User Keying Material" --aead aes256-gcm --auth-env-data -c ./output/mlkem512-2.16.840.1.101.3.4.4.1_ee.der
./kemri_toy -o output -u "This is some User Keying Material" --aead aes256-gcm --auth-env-data -c ./output/mlkem768-2.16.840.1.101.3.4.4.2_ee.der
./kemri_toy -o output -u "This is some User Keying Material" --aead aes256-gcm --auth-env-data -c ./output/mlkem1024-2.16.840.1.101.3.4.4.3_ee.der
./kemri_toy -o output -u "This is some User Keying Material" --aead aes256-gcm --auth-env-data -c ./output/id-MLKEM768-RSA2048-SHA3-256-2.16.840.1.114027.80.5.2.74_ee.der
./kemri_toy -o output -u "This is some User Keying Material" --aead aes256-gcm --auth-env-data -c ./output/id-MLKEM768-RSA3072-SHA3-256-2.16.840.1.114027.80.5.2.75_ee.der
./kemri_toy -o output -u "This is some User Keying Material" --aead aes256-gcm --auth-env-data -c ./output/id-MLKEM768-RSA4096-SHA3-256-2.16.840.1.114027.80.5.2.76_ee.der
./kemri_toy -o output -u "This is some User Keying Material" --aead aes256-gcm --auth-env-data -c ./output/id-MLKEM1024-RSA3072-SHA3-256-2.16.840.1.114027.80.5.2.81_ee.der
./kemri_toy -o output -u "This is some User Keying Material" --aead aes256-gcm --auth-env-data -c ./output/id-MLKEM768-ECDH-P256-SHA3-256-2.16.840.1.114027.80.5.2.78_ee.der
./kemri_toy -o output -u "This is some User Keying Material" --aead aes256-gcm --auth-env-data -c ./output/id-MLKEM768-ECDH-P384-SHA3-256-2.16.840.1.114027.80.5.2.79_ee.der
./kemri_toy -o output -u "This is some User Keying Material" --aead aes256-gcm --auth-env-data -c ./output/id-MLKEM1024-ECDH-P384-SHA3-256-2.16.840.1.114027.80.5.2.82_ee.der
./kemri_toy -o output -u "This is some User Keying Material" --aead aes256-gcm --auth-env-data -c ./output/id-MLKEM1024-ECDH-P521-SHA3-256-2.16.840.1.114027.80.5.2.85_ee.der

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
./kemri_toy -i ./output/id-MLKEM768-RSA2048-SHA3-256-2.16.840.1.114027.80.5.2.74_kemri_auth_id-alg-hkdf-with-sha256_ukm.der -k ./output/id-MLKEM768-RSA2048-SHA3-256-2.16.840.1.114027.80.5.2.74_priv.der
./kemri_toy -i ./output/id-MLKEM768-RSA3072-SHA3-256-2.16.840.1.114027.80.5.2.75_kemri_auth_id-alg-hkdf-with-sha256_ukm.der -k ./output/id-MLKEM768-RSA3072-SHA3-256-2.16.840.1.114027.80.5.2.75_priv.der
./kemri_toy -i ./output/id-MLKEM768-RSA4096-SHA3-256-2.16.840.1.114027.80.5.2.76_kemri_auth_id-alg-hkdf-with-sha256_ukm.der -k ./output/id-MLKEM768-RSA4096-SHA3-256-2.16.840.1.114027.80.5.2.76_priv.der
./kemri_toy -i ./output/id-MLKEM768-ECDH-P256-SHA3-256-2.16.840.1.114027.80.5.2.78_kemri_auth_id-alg-hkdf-with-sha256_ukm.der -k ./output/id-MLKEM768-ECDH-P256-SHA3-256-2.16.840.1.114027.80.5.2.78_priv.der
./kemri_toy -i ./output/id-MLKEM768-ECDH-P384-SHA3-256-2.16.840.1.114027.80.5.2.79_kemri_auth_id-alg-hkdf-with-sha256_ukm.der -k ./output/id-MLKEM768-ECDH-P384-SHA3-256-2.16.840.1.114027.80.5.2.79_priv.der
./kemri_toy -i ./output/id-MLKEM1024-RSA3072-SHA3-256-2.16.840.1.114027.80.5.2.81_kemri_auth_id-alg-hkdf-with-sha256_ukm.der -k ./output/id-MLKEM1024-RSA3072-SHA3-256-2.16.840.1.114027.80.5.2.81_priv.der
./kemri_toy -i ./output/id-MLKEM1024-ECDH-P384-SHA3-256-2.16.840.1.114027.80.5.2.82_kemri_auth_id-alg-hkdf-with-sha256_ukm.der -k ./output/id-MLKEM1024-ECDH-P384-SHA3-256-2.16.840.1.114027.80.5.2.82_priv.der
./kemri_toy -i ./output/id-MLKEM1024-ECDH-P521-SHA3-256-2.16.840.1.114027.80.5.2.85_kemri_auth_id-alg-hkdf-with-sha256_ukm.der -k ./output/id-MLKEM1024-ECDH-P521-SHA3-256-2.16.840.1.114027.80.5.2.85_priv.der


