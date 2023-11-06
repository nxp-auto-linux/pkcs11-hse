**NXP HSE PKCS#11 Module**
======================

**1. Prerequisites**
--------------

The current implementation has been tested with the following:

* libp11 0.4.11 (2020-Oct-11)
* OpenSSL 1.1.1 (2018-Sep-11)

The HSE PKCS11 module is compiled for `aarch64`, and depends on both libp11 and OpenSSL.
As such, libp11 and OpenSSL need to be cross-compiled for `aarch64`, as well.

Take note that the paths provided in the following sections are provided simply as
examples, and can be changed to fit your build environment.

Before you begin cross-compiling, make sure you have a cross-compiler installed, which fits
your desired target system's architecture. Furthermore, you should export a `CROSS_COMPILE`
environment variable, which will be auto-detected by the makefiles of the projects. Your
`CROSS_COMPILE` env var should resemble the following:

```
export CROSS_COMPILE=<path/to/cross/compiler>/aarch64-linux-gnu-
```

**Going forth, it will be assumed you have set your `CROSS_COMPILE` env var.**

### 1.1. Cross-compiling libp11 0.4.11 for aarch64

First, you will need the source code, which you can download from the project's GitHub page:

https://github.com/OpenSC/libp11/releases

Next, you'll need to configure the build system for `aarch64` cross-compilation:

```
./configure --host=aarch64-linux-gnu --prefix=$HOME/libp11-aarch64
```

`--host` will (confusingly) specify the **target** architecture, while `--prefix` will indicate a directory
separate from your host's file system in which to place the cross-compiled files. The path provided for
`--prefix` is an example.

You can now build libp11:

```
make
sudo make install
```

You can find the compiled files under `$HOME/libp11-aarch64`.

### 1.2. Cross-compiling OpenSSL 1.1.1 for aarch64

First, you will need the source code, which can be download from the project's website:

https://www.openssl.org/source/old/1.1.1/

Next, you'll need to configure the build system for `aarch64` cross-compilation:

```
./Configure linux-aarch64 --prefix=$HOME/openssl-aarch64
```

As before, `--prefix` will indicate a directory separate from your host's file system in which to place the
cross-compiled files. The path provided is an example.

You can now build OpenSSL:

```
make
sudo make install
```

You can find the compiled files under `$HOME/openssl-aarch64`.

**2. Building the HSE PKCS11 module**
------------------------------

Assuming you have set your `CROSS_COMPILE` env var, compilation is straight-forward. From the pkcs11-hse
repo, run:

```
make
```

and the `pkcs11-hse.so` file will be compiled. This is the module that is the middle man in communication
between OpenSSL/libp11 and HSE.

### 2.1. Building the HSE PKCS11 modules example

A usage example is provided in the repo under `examples/`. The sample application will link against
OpenSSL (libcrypto) and libp11 (libp11) to use functions provided by both. In short,
what the application does is:

1. initialize libp11 with the pkcs11-hse.so module
2. find the slot and token corresponding to HSE
3. use openssl to generate an RSA key pair
4. store the key pair in HSE
5. enumerate the stored keys
6. remove the key pair from HSE

Since the application must be linked against both libcrypto and libp11, the directories in which
the cross-compiled OpenSSL and libp11 are stored must be specified:

```
make OPENSSL_DIR=$HOME/openssl-aarch64 LIBP11_DIR=$HOME/libp11-aarch64
```

Moreover, since the application is dynamically linked, both libcrypto and libp11 **must**
be present in the target's file system, (usually) under `/usr/lib/`. In this case, you can
use the files under `openssl-aarch64/lib/` and `libp11-aarch64/lib/`, and copy
the `libp11.so.*` and `libcrypto.so.*` files to the target's `/usr/lib/` directory.

Afterwards, you can run the example on the target system:

```
./pkcs-keyop <path>/pkcs11-hse.so
```

The application will output a message for each step described previously.

### 2.2. Building the OpenSC pkcs11-tool

First, you will need the source code, which can be download from the project's GitHub page:

https://github.com/OpenSC/OpenSC/releases

This release has been tested with OpenSC-0.21.0. Make sure to install the pre-requisites beforehand:

```
sudo apt-get install pcscd libccid libpcsclite-dev libssl-dev libreadline-dev autoconf automake build-essential docbook-xsl xsltproc libtool pkg-config
```

Next, you'll need to configure the build system for `aarch64` cross-compilation. You'll also need to
have cross-compiled OpenSSL beforehand, since OpenSC needs to link against it:

```
./bootstrap
./configure --host=aarch64-linux --prefix=$HOME/opensc-aarch64-test --enable-openssl \
	CC= <path>/<to>/<cross>/<compiler>/aarch64-linux-gnu-gcc \
	LDFLAGS=-g -Wl,-rpath,$HOME/openssl-aarch64/lib \
	OPENSSL_LIBS=-lcrypto -L$HOME/openssl-aarch64/lib \
	OPENSSL_CFLAGS=-I$HOME/openssl-aarch64/include
```

As before, `--prefix` will indicate a directory separate from your host's file system in which to place the
cross-compiled files. The path provided is an example.

You can now build OpenSC:

```
make
sudo make install
```

You can find the compiled files under `$HOME/opensc-aarch64`. You'll need to place `opensc-aarch64/lib/libopensc.so.7.0.0`
in the target's `lib` directory (e.g. in `/usr/lib`); `opensc-aarch64/bin/pkcs11-tool` can be placed
anywhere on the target (e.g. `/home/<user>`).

You can use `pkcs11-tool` to load RSA keys (public/pair), EC keys (public) and AES keys. The `--id` switch corresponds
to the key's number (`00`), slot (`06`) and catalog (`01`), in hexadecimal, from the HSE Key Catalog. Some examples:

```
./pkcs11-tool --module ~/pkcs11-hse.so --write-object /<path>/rsa_keypair.der --type privkey --id 000601 --label "HSE-RSAPRIV-KEY"
./pkcs11-tool --module ~/pkcs11-hse.so --write-object /<path>/rsa_keypub.der --type pubkey --id 000501 --label "HSE-RSAPUB-KEY"
./pkcs11-tool --module ~/pkcs11-hse.so --write-object /<path>/ec_keypub.der --type pubkey --id 000401 --label "HSE-ECPUB-prime256v1-KEY"
./pkcs11-tool --module ~/pkcs11-hse.so --write-object /<path>/aes.key --type secrkey --key-type AES:256 --id 000101 --label "HSE-AES-256-KEY"
```

The tool will display a message if the key import operation is successful.
