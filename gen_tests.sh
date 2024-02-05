./kemri_toy -o output
./kemri_toy -o output -c ./output/1.3.6.1.4.1.22554.5.6.1_ee.der --kdf hkdf-sha384
./kemri_toy -o output -c ./output/1.3.6.1.4.1.22554.5.6.1_ee.der --kdf hkdf-sha512
./kemri_toy -o output --kem ml-kem768
./kemri_toy -o output -c ./output/1.3.6.1.4.1.22554.5.6.2_ee.der --kem ml-kem768 --kdf hkdf-sha384
./kemri_toy -o output -c ./output/1.3.6.1.4.1.22554.5.6.2_ee.der --kem ml-kem768 --kdf hkdf-sha512
./kemri_toy -o output --kem ml-kem1024
./kemri_toy -o output -c ./output/1.3.6.1.4.1.22554.5.6.3_ee.der --kem ml-kem1024 --kdf hkdf-sha384
./kemri_toy -o output -c ./output/1.3.6.1.4.1.22554.5.6.3_ee.der --kem ml-kem1024 --kdf hkdf-sha512
./kemri_toy -i ./output/1.3.6.1.4.1.22554.5.6.1_enveloped_id-alg-hkdf-with-sha256.der -k ./output/1.3.6.1.4.1.22554.5.6.1_priv.der
./kemri_toy -i ./output/1.3.6.1.4.1.22554.5.6.1_enveloped_id-alg-hkdf-with-sha384.der -k ./output/1.3.6.1.4.1.22554.5.6.1_priv.der
./kemri_toy -i ./output/1.3.6.1.4.1.22554.5.6.1_enveloped_id-alg-hkdf-with-sha512.der -k ./output/1.3.6.1.4.1.22554.5.6.1_priv.der
./kemri_toy -i ./output/1.3.6.1.4.1.22554.5.6.2_enveloped_id-alg-hkdf-with-sha256.der -k ./output/1.3.6.1.4.1.22554.5.6.2_priv.der
./kemri_toy -i ./output/1.3.6.1.4.1.22554.5.6.2_enveloped_id-alg-hkdf-with-sha384.der -k ./output/1.3.6.1.4.1.22554.5.6.2_priv.der
./kemri_toy -i ./output/1.3.6.1.4.1.22554.5.6.2_enveloped_id-alg-hkdf-with-sha512.der -k ./output/1.3.6.1.4.1.22554.5.6.2_priv.der
./kemri_toy -i ./output/1.3.6.1.4.1.22554.5.6.3_enveloped_id-alg-hkdf-with-sha256.der -k ./output/1.3.6.1.4.1.22554.5.6.3_priv.der
./kemri_toy -i ./output/1.3.6.1.4.1.22554.5.6.3_enveloped_id-alg-hkdf-with-sha384.der -k ./output/1.3.6.1.4.1.22554.5.6.3_priv.der
./kemri_toy -i ./output/1.3.6.1.4.1.22554.5.6.3_enveloped_id-alg-hkdf-with-sha512.der -k ./output/1.3.6.1.4.1.22554.5.6.3_priv.der

./kemri_toy -o output -u "This is some User Keying Material" -c ./output/1.3.6.1.4.1.22554.5.6.1_ee.der
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/1.3.6.1.4.1.22554.5.6.1_ee.der --kdf hkdf-sha384
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/1.3.6.1.4.1.22554.5.6.1_ee.der --kdf hkdf-sha512
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/1.3.6.1.4.1.22554.5.6.2_ee.der --kem ml-kem768
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/1.3.6.1.4.1.22554.5.6.2_ee.der --kem ml-kem768 --kdf hkdf-sha384
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/1.3.6.1.4.1.22554.5.6.2_ee.der --kem ml-kem768 --kdf hkdf-sha512
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/1.3.6.1.4.1.22554.5.6.3_ee.der --kem ml-kem1024
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/1.3.6.1.4.1.22554.5.6.3_ee.der --kem ml-kem1024 --kdf hkdf-sha384
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/1.3.6.1.4.1.22554.5.6.3_ee.der --kem ml-kem1024 --kdf hkdf-sha512
./kemri_toy -i ./output/1.3.6.1.4.1.22554.5.6.1_enveloped_id-alg-hkdf-with-sha256_ukm.der -k ./output/1.3.6.1.4.1.22554.5.6.1_priv.der
./kemri_toy -i ./output/1.3.6.1.4.1.22554.5.6.1_enveloped_id-alg-hkdf-with-sha384_ukm.der -k ./output/1.3.6.1.4.1.22554.5.6.1_priv.der
./kemri_toy -i ./output/1.3.6.1.4.1.22554.5.6.1_enveloped_id-alg-hkdf-with-sha512_ukm.der -k ./output/1.3.6.1.4.1.22554.5.6.1_priv.der
./kemri_toy -i ./output/1.3.6.1.4.1.22554.5.6.2_enveloped_id-alg-hkdf-with-sha256_ukm.der -k ./output/1.3.6.1.4.1.22554.5.6.2_priv.der
./kemri_toy -i ./output/1.3.6.1.4.1.22554.5.6.2_enveloped_id-alg-hkdf-with-sha384_ukm.der -k ./output/1.3.6.1.4.1.22554.5.6.2_priv.der
./kemri_toy -i ./output/1.3.6.1.4.1.22554.5.6.2_enveloped_id-alg-hkdf-with-sha512_ukm.der -k ./output/1.3.6.1.4.1.22554.5.6.2_priv.der
./kemri_toy -i ./output/1.3.6.1.4.1.22554.5.6.3_enveloped_id-alg-hkdf-with-sha256_ukm.der -k ./output/1.3.6.1.4.1.22554.5.6.3_priv.der
./kemri_toy -i ./output/1.3.6.1.4.1.22554.5.6.3_enveloped_id-alg-hkdf-with-sha384_ukm.der -k ./output/1.3.6.1.4.1.22554.5.6.3_priv.der
./kemri_toy -i ./output/1.3.6.1.4.1.22554.5.6.3_enveloped_id-alg-hkdf-with-sha512_ukm.der -k ./output/1.3.6.1.4.1.22554.5.6.3_priv.der


./kemri_toy -o output --aead aes256-gcm --auth-env-data -c ./output/1.3.6.1.4.1.22554.5.6.1_ee.der
./kemri_toy -o output -c ./output/1.3.6.1.4.1.22554.5.6.1_ee.der --kdf hkdf-sha384 --aead aes256-gcm --auth-env-data
./kemri_toy -o output -c ./output/1.3.6.1.4.1.22554.5.6.1_ee.der --kdf hkdf-sha512 --aead aes256-gcm --auth-env-data
./kemri_toy -o output --kem ml-kem768 --aead aes256-gcm --auth-env-data -c ./output/1.3.6.1.4.1.22554.5.6.2_ee.der
./kemri_toy -o output -c ./output/1.3.6.1.4.1.22554.5.6.2_ee.der --kem ml-kem768 --kdf hkdf-sha384 --aead aes256-gcm --auth-env-data
./kemri_toy -o output -c ./output/1.3.6.1.4.1.22554.5.6.2_ee.der --kem ml-kem768 --kdf hkdf-sha512 --aead aes256-gcm --auth-env-data
./kemri_toy -o output --kem ml-kem1024 --aead aes256-gcm --auth-env-data -c ./output/1.3.6.1.4.1.22554.5.6.3_ee.der
./kemri_toy -o output -c ./output/1.3.6.1.4.1.22554.5.6.3_ee.der --kem ml-kem1024 --kdf hkdf-sha384 --aead aes256-gcm --auth-env-data
./kemri_toy -o output -c ./output/1.3.6.1.4.1.22554.5.6.3_ee.der --kem ml-kem1024 --kdf hkdf-sha512 --aead aes256-gcm --auth-env-data
./kemri_toy -i ./output/1.3.6.1.4.1.22554.5.6.1_enveloped_id-alg-hkdf-with-sha256.der -k ./output/1.3.6.1.4.1.22554.5.6.1_priv.der
./kemri_toy -i ./output/1.3.6.1.4.1.22554.5.6.1_enveloped_id-alg-hkdf-with-sha384.der -k ./output/1.3.6.1.4.1.22554.5.6.1_priv.der
./kemri_toy -i ./output/1.3.6.1.4.1.22554.5.6.1_enveloped_id-alg-hkdf-with-sha512.der -k ./output/1.3.6.1.4.1.22554.5.6.1_priv.der
./kemri_toy -i ./output/1.3.6.1.4.1.22554.5.6.2_enveloped_id-alg-hkdf-with-sha256.der -k ./output/1.3.6.1.4.1.22554.5.6.2_priv.der
./kemri_toy -i ./output/1.3.6.1.4.1.22554.5.6.2_enveloped_id-alg-hkdf-with-sha384.der -k ./output/1.3.6.1.4.1.22554.5.6.2_priv.der
./kemri_toy -i ./output/1.3.6.1.4.1.22554.5.6.2_enveloped_id-alg-hkdf-with-sha512.der -k ./output/1.3.6.1.4.1.22554.5.6.2_priv.der
./kemri_toy -i ./output/1.3.6.1.4.1.22554.5.6.3_enveloped_id-alg-hkdf-with-sha256.der -k ./output/1.3.6.1.4.1.22554.5.6.3_priv.der
./kemri_toy -i ./output/1.3.6.1.4.1.22554.5.6.3_enveloped_id-alg-hkdf-with-sha384.der -k ./output/1.3.6.1.4.1.22554.5.6.3_priv.der
./kemri_toy -i ./output/1.3.6.1.4.1.22554.5.6.3_enveloped_id-alg-hkdf-with-sha512.der -k ./output/1.3.6.1.4.1.22554.5.6.3_priv.der

./kemri_toy -o output -u "This is some User Keying Material" -c ./output/1.3.6.1.4.1.22554.5.6.1_ee.der --aead aes256-gcm --auth-env-data
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/1.3.6.1.4.1.22554.5.6.1_ee.der --kdf hkdf-sha384 --aead aes256-gcm --auth-env-data
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/1.3.6.1.4.1.22554.5.6.1_ee.der --kdf hkdf-sha512 --aead aes256-gcm --auth-env-data
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/1.3.6.1.4.1.22554.5.6.2_ee.der --kem ml-kem768 --aead aes256-gcm --auth-env-data
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/1.3.6.1.4.1.22554.5.6.2_ee.der --kem ml-kem768 --kdf hkdf-sha384 --aead aes256-gcm --auth-env-data
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/1.3.6.1.4.1.22554.5.6.2_ee.der --kem ml-kem768 --kdf hkdf-sha512 --aead aes256-gcm --auth-env-data
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/1.3.6.1.4.1.22554.5.6.3_ee.der --kem ml-kem1024 --aead aes256-gcm --auth-env-data
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/1.3.6.1.4.1.22554.5.6.3_ee.der --kem ml-kem1024 --kdf hkdf-sha384 --aead aes256-gcm --auth-env-data
./kemri_toy -o output -u "This is some User Keying Material" -c ./output/1.3.6.1.4.1.22554.5.6.3_ee.der --kem ml-kem1024 --kdf hkdf-sha512 --aead aes256-gcm --auth-env-data
./kemri_toy -i ./output/1.3.6.1.4.1.22554.5.6.1_enveloped_id-alg-hkdf-with-sha256_ukm.der -k ./output/1.3.6.1.4.1.22554.5.6.1_priv.der
./kemri_toy -i ./output/1.3.6.1.4.1.22554.5.6.1_enveloped_id-alg-hkdf-with-sha384_ukm.der -k ./output/1.3.6.1.4.1.22554.5.6.1_priv.der
./kemri_toy -i ./output/1.3.6.1.4.1.22554.5.6.1_enveloped_id-alg-hkdf-with-sha512_ukm.der -k ./output/1.3.6.1.4.1.22554.5.6.1_priv.der
./kemri_toy -i ./output/1.3.6.1.4.1.22554.5.6.2_enveloped_id-alg-hkdf-with-sha256_ukm.der -k ./output/1.3.6.1.4.1.22554.5.6.2_priv.der
./kemri_toy -i ./output/1.3.6.1.4.1.22554.5.6.2_enveloped_id-alg-hkdf-with-sha384_ukm.der -k ./output/1.3.6.1.4.1.22554.5.6.2_priv.der
./kemri_toy -i ./output/1.3.6.1.4.1.22554.5.6.2_enveloped_id-alg-hkdf-with-sha512_ukm.der -k ./output/1.3.6.1.4.1.22554.5.6.2_priv.der
./kemri_toy -i ./output/1.3.6.1.4.1.22554.5.6.3_enveloped_id-alg-hkdf-with-sha256_ukm.der -k ./output/1.3.6.1.4.1.22554.5.6.3_priv.der
./kemri_toy -i ./output/1.3.6.1.4.1.22554.5.6.3_enveloped_id-alg-hkdf-with-sha384_ukm.der -k ./output/1.3.6.1.4.1.22554.5.6.3_priv.der
./kemri_toy -i ./output/1.3.6.1.4.1.22554.5.6.3_enveloped_id-alg-hkdf-with-sha512_ukm.der -k ./output/1.3.6.1.4.1.22554.5.6.3_priv.der
