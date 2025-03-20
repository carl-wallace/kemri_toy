./kemri_toy -o output
./kemri_toy -o output -c ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_ee.der --kdf hkdf-sha384
./kemri_toy -o output -c ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_ee.der --kdf hkdf-sha512
./kemri_toy -o output -c ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_ee.der --kdf kmac128
./kemri_toy -o output -c ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_ee.der --kdf kmac256
./kemri_toy -o output --kem ml-kem768
./kemri_toy -o output -c ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_ee.der --kem ml-kem768 --kdf hkdf-sha384
./kemri_toy -o output -c ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_ee.der --kem ml-kem768 --kdf hkdf-sha512
./kemri_toy -o output -c ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_ee.der --kem ml-kem768 --kdf kmac128
./kemri_toy -o output -c ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_ee.der --kem ml-kem768 --kdf kmac256
./kemri_toy -o output --kem ml-kem1024
./kemri_toy -o output -c ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_ee.der --kem ml-kem1024 --kdf hkdf-sha384
./kemri_toy -o output -c ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_ee.der --kem ml-kem1024 --kdf hkdf-sha512
./kemri_toy -o output -c ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_ee.der --kem ml-kem1024 --kdf kmac128
./kemri_toy -o output -c ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_ee.der --kem ml-kem1024 --kdf kmac256
./kemri_toy -i ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_kemri_id-alg-hkdf-with-sha256.der -k ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_expandedkey_priv.der
./kemri_toy -i ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_kemri_id-alg-hkdf-with-sha384.der -k ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_expandedkey_priv.der
./kemri_toy -i ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_kemri_id-alg-hkdf-with-sha512.der -k ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_expandedkey_priv.der
./kemri_toy -i ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_kemri_id-kmac128.der -k ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_expandedkey_priv.der
./kemri_toy -i ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_kemri_id-kmac256.der -k ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_expandedkey_priv.der
./kemri_toy -i ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_kemri_id-alg-hkdf-with-sha256.der -k ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_expandedkey_priv.der
./kemri_toy -i ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_kemri_id-alg-hkdf-with-sha384.der -k ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_expandedkey_priv.der
./kemri_toy -i ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_kemri_id-alg-hkdf-with-sha512.der -k ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_expandedkey_priv.der
./kemri_toy -i ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_kemri_id-kmac128.der -k ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_expandedkey_priv.der
./kemri_toy -i ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_kemri_id-kmac256.der -k ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_expandedkey_priv.der
./kemri_toy -i ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_kemri_id-alg-hkdf-with-sha256.der -k ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_expandedkey_priv.der
./kemri_toy -i ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_kemri_id-alg-hkdf-with-sha384.der -k ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_expandedkey_priv.der
./kemri_toy -i ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_kemri_id-alg-hkdf-with-sha512.der -k ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_expandedkey_priv.der
./kemri_toy -i ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_kemri_id-kmac128.der -k ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_expandedkey_priv.der
./kemri_toy -i ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_kemri_id-kmac256.der -k ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_expandedkey_priv.der

./kemri_toy -o output -u "This is some User Keying Material" -c ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_ee.der
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_ee.der --kdf hkdf-sha384
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_ee.der --kdf hkdf-sha512
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_ee.der --kdf kmac128
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_ee.der --kdf kmac256
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_ee.der --kem ml-kem768
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_ee.der --kem ml-kem768 --kdf hkdf-sha384
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_ee.der --kem ml-kem768 --kdf hkdf-sha512
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_ee.der --kem ml-kem768 --kdf kmac128
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_ee.der --kem ml-kem768 --kdf kmac256
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_ee.der --kem ml-kem1024
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_ee.der --kem ml-kem1024 --kdf hkdf-sha384
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_ee.der --kem ml-kem1024 --kdf hkdf-sha512
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_ee.der --kem ml-kem1024 --kdf kmac128
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_ee.der --kem ml-kem1024 --kdf kmac256
./kemri_toy -i ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_kemri_id-alg-hkdf-with-sha256_ukm.der -k ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_expandedkey_priv.der
./kemri_toy -i ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_kemri_id-alg-hkdf-with-sha384_ukm.der -k ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_expandedkey_priv.der
./kemri_toy -i ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_kemri_id-alg-hkdf-with-sha512_ukm.der -k ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_expandedkey_priv.der
./kemri_toy -i ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_kemri_id-kmac128_ukm.der -k ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_expandedkey_priv.der
./kemri_toy -i ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_kemri_id-kmac256_ukm.der -k ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_expandedkey_priv.der
./kemri_toy -i ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_kemri_id-alg-hkdf-with-sha256_ukm.der -k ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_expandedkey_priv.der
./kemri_toy -i ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_kemri_id-alg-hkdf-with-sha384_ukm.der -k ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_expandedkey_priv.der
./kemri_toy -i ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_kemri_id-alg-hkdf-with-sha512_ukm.der -k ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_expandedkey_priv.der
./kemri_toy -i ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_kemri_id-kmac128_ukm.der -k ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_expandedkey_priv.der
./kemri_toy -i ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_kemri_id-kmac256_ukm.der -k ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_expandedkey_priv.der
./kemri_toy -i ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_kemri_id-alg-hkdf-with-sha256_ukm.der -k ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_expandedkey_priv.der
./kemri_toy -i ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_kemri_id-alg-hkdf-with-sha384_ukm.der -k ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_expandedkey_priv.der
./kemri_toy -i ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_kemri_id-alg-hkdf-with-sha512_ukm.der -k ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_expandedkey_priv.der
./kemri_toy -i ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_kemri_id-kmac128_ukm.der -k ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_expandedkey_priv.der
./kemri_toy -i ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_kemri_id-kmac256_ukm.der -k ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_expandedkey_priv.der


./kemri_toy -o output --aead aes256-gcm --auth-env-data -c ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_ee.der
./kemri_toy -o output -c ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_ee.der --kdf hkdf-sha384 --aead aes256-gcm --auth-env-data
./kemri_toy -o output -c ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_ee.der --kdf hkdf-sha512 --aead aes256-gcm --auth-env-data
./kemri_toy -o output -c ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_ee.der --kdf kmac128 --aead aes256-gcm --auth-env-data
./kemri_toy -o output -c ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_ee.der --kdf kmac256 --aead aes256-gcm --auth-env-data
./kemri_toy -o output --kem ml-kem768 --aead aes256-gcm --auth-env-data -c ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_ee.der
./kemri_toy -o output -c ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_ee.der --kem ml-kem768 --kdf hkdf-sha384 --aead aes256-gcm --auth-env-data
./kemri_toy -o output -c ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_ee.der --kem ml-kem768 --kdf hkdf-sha512 --aead aes256-gcm --auth-env-data
./kemri_toy -o output -c ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_ee.der --kem ml-kem768 --kdf kmac128 --aead aes256-gcm --auth-env-data
./kemri_toy -o output -c ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_ee.der --kem ml-kem768 --kdf kmac256 --aead aes256-gcm --auth-env-data
./kemri_toy -o output --kem ml-kem1024 --aead aes256-gcm --auth-env-data -c ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_ee.der
./kemri_toy -o output -c ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_ee.der --kem ml-kem1024 --kdf hkdf-sha384 --aead aes256-gcm --auth-env-data
./kemri_toy -o output -c ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_ee.der --kem ml-kem1024 --kdf hkdf-sha512 --aead aes256-gcm --auth-env-data
./kemri_toy -o output -c ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_ee.der --kem ml-kem1024 --kdf kmac128 --aead aes256-gcm --auth-env-data
./kemri_toy -o output -c ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_ee.der --kem ml-kem1024 --kdf kmac256 --aead aes256-gcm --auth-env-data
./kemri_toy -i ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_kemri_auth_id-alg-hkdf-with-sha256.der -k ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_expandedkey_priv.der
./kemri_toy -i ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_kemri_auth_id-alg-hkdf-with-sha384.der -k ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_expandedkey_priv.der
./kemri_toy -i ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_kemri_auth_id-alg-hkdf-with-sha512.der -k ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_expandedkey_priv.der
./kemri_toy -i ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_kemri_auth_id-kmac128.der -k ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_expandedkey_priv.der
./kemri_toy -i ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_kemri_auth_id-kmac256.der -k ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_expandedkey_priv.der
./kemri_toy -i ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_kemri_auth_id-alg-hkdf-with-sha256.der -k ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_expandedkey_priv.der
./kemri_toy -i ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_kemri_auth_id-alg-hkdf-with-sha384.der -k ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_expandedkey_priv.der
./kemri_toy -i ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_kemri_auth_id-alg-hkdf-with-sha512.der -k ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_expandedkey_priv.der
./kemri_toy -i ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_kemri_auth_id-kmac128.der -k ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_expandedkey_priv.der
./kemri_toy -i ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_kemri_auth_id-kmac256.der -k ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_expandedkey_priv.der
./kemri_toy -i ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_kemri_auth_id-alg-hkdf-with-sha256.der -k ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_expandedkey_priv.der
./kemri_toy -i ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_kemri_auth_id-alg-hkdf-with-sha384.der -k ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_expandedkey_priv.der
./kemri_toy -i ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_kemri_auth_id-alg-hkdf-with-sha512.der -k ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_expandedkey_priv.der
./kemri_toy -i ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_kemri_auth_id-kmac128.der -k ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_expandedkey_priv.der
./kemri_toy -i ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_kemri_auth_id-kmac256.der -k ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_expandedkey_priv.der

./kemri_toy -o output -u "This is some User Keying Material" -c ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_ee.der --aead aes256-gcm --auth-env-data
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_ee.der --kdf hkdf-sha384 --aead aes256-gcm --auth-env-data
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_ee.der --kdf hkdf-sha512 --aead aes256-gcm --auth-env-data
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_ee.der --kdf kmac128 --aead aes256-gcm --auth-env-data
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_ee.der --kdf kmac256 --aead aes256-gcm --auth-env-data
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_ee.der --kem ml-kem768 --aead aes256-gcm --auth-env-data
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_ee.der --kem ml-kem768 --kdf hkdf-sha384 --aead aes256-gcm --auth-env-data
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_ee.der --kem ml-kem768 --kdf hkdf-sha512 --aead aes256-gcm --auth-env-data
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_ee.der --kem ml-kem768 --kdf kmac128 --aead aes256-gcm --auth-env-data
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_ee.der --kem ml-kem768 --kdf kmac256 --aead aes256-gcm --auth-env-data
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_ee.der --kem ml-kem1024 --aead aes256-gcm --auth-env-data
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_ee.der --kem ml-kem1024 --kdf hkdf-sha384 --aead aes256-gcm --auth-env-data
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_ee.der --kem ml-kem1024 --kdf hkdf-sha512 --aead aes256-gcm --auth-env-data
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_ee.der --kem ml-kem1024 --kdf kmac128 --aead aes256-gcm --auth-env-data
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_ee.der --kem ml-kem1024 --kdf kmac256 --aead aes256-gcm --auth-env-data
./kemri_toy -i ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_kemri_auth_id-alg-hkdf-with-sha256_ukm.der -k ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_expandedkey_priv.der
./kemri_toy -i ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_kemri_auth_id-alg-hkdf-with-sha384_ukm.der -k ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_expandedkey_priv.der
./kemri_toy -i ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_kemri_auth_id-alg-hkdf-with-sha512_ukm.der -k ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_expandedkey_priv.der
./kemri_toy -i ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_kemri_auth_id-kmac128_ukm.der -k ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_expandedkey_priv.der
./kemri_toy -i ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_kemri_auth_id-kmac256_ukm.der -k ./output/ml-kem-512-2.16.840.1.101.3.4.4.1_expandedkey_priv.der
./kemri_toy -i ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_kemri_auth_id-alg-hkdf-with-sha256_ukm.der -k ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_expandedkey_priv.der
./kemri_toy -i ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_kemri_auth_id-alg-hkdf-with-sha384_ukm.der -k ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_expandedkey_priv.der
./kemri_toy -i ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_kemri_auth_id-alg-hkdf-with-sha512_ukm.der -k ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_expandedkey_priv.der
./kemri_toy -i ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_kemri_auth_id-kmac128_ukm.der -k ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_expandedkey_priv.der
./kemri_toy -i ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_kemri_auth_id-kmac256_ukm.der -k ./output/ml-kem-768-2.16.840.1.101.3.4.4.2_expandedkey_priv.der
./kemri_toy -i ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_kemri_auth_id-alg-hkdf-with-sha256_ukm.der -k ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_expandedkey_priv.der
./kemri_toy -i ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_kemri_auth_id-alg-hkdf-with-sha384_ukm.der -k ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_expandedkey_priv.der
./kemri_toy -i ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_kemri_auth_id-alg-hkdf-with-sha512_ukm.der -k ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_expandedkey_priv.der
./kemri_toy -i ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_kemri_auth_id-kmac128_ukm.der -k ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_expandedkey_priv.der
./kemri_toy -i ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_kemri_auth_id-kmac256_ukm.der -k ./output/ml-kem-1024-2.16.840.1.101.3.4.4.3_expandedkey_priv.der

