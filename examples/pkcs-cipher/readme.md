This example assumes the RSA private key and public key were installed beforehand.
Please take the below steps as referance:

1. Format HSE key catalogs using the `hse-secboot` example

    hse-secboot -f -o -d /dev/mmcblk0

    Note: `-o` is required if the HSE SYS_IMG exist.

2. Remove the objects file after re-formating HSE key catalogs

    rm /etc/pkcs-hse-objs

    Note: This keeps the objects file consistent with HSE key catalog

3. Import RSA private and public keys using pkcs11-tool from OpenSC.

    pkcs11-tool --module /<path>/libpkcs-hse.so --write-object rsa_priv.pem --type privkey --label "HSE-RSAPRIV-KEY" --usage-decrypt --usage-sign

    pkcs11-tool --module /<path>/libpkcs-hse.so --write-object rsa_pub.pem --type pubkey --label "HSE-RSAPUB-KEY" --usage-decrypt --usage-sign

4. Run the pkcs-cipher

    pkcs-cipher /<path>/libpkcs-hse.so

