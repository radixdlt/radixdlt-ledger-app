# RadixDLT Ledger app
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

This repository contains:

- Ledger Nano S/X Radix app
- Specs / Documentation
- C++ unit tests

# Test APDU commands
Using [Python program 'ledgerblue'](https://github.com/LedgerHQ/blue-loader-python). you can send APDU commands from your host machine to the Ledger in order to test this app. Send APDU commands as a byte array (hex), with big endian byte order. Use `AA` as first prefix since that is our APDU CLA. Check [the APDU specification](docs/APDUSPEC.md) for the INS byte of the instruction wou wanna invoke.

## Examples


### Generate Public Key
Example of generation of public key (`INS_GET_PUB_KEY_SECP256K1`), you can use CLI and send a command to the ledger useing

```sh
echo 'AA0801010C800000020000000100000003' | python -m ledgerblue.runScript --targetId 0x31100004 --apdu
```

Should result in this BIP path: `44'/536'/2'/1/3`. And using the mnemonic mentioned below (`equip will roof....`), ought to result in this compressed public key `026d5e07cfde5df84b5ef884b629d28d15b0f6c66be229680699767cd57c618288`.

### SIGN HASH

```sh
echo 'AA0400002C800000020000000100000003deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef' | python -m ledgerblue.runScript --targetId 0x31100004 --apdu
```

Should result in this BIP path: `44'/536'/2'/1/3`. And using the mnemonic mentioned below (`equip will roof....`), ought to result in the ECDSA signature (DER decoded to just `R | S`): 

`098c1526d623f61a1adc1d42b818e668fdb3c6b99a0055435731221211b1cd11324b979a56c9ded9f5b645389e575dc7fc3c9b3aa180bc379fa6cb3d912503e1`

### SIGN ATOM (in progress)
Currently just supporting some CBOR decoding.

```sh
echo 'AA02000006655261646978' | python -m ledgerblue.runScript --targetId 0x31100004 --apdu
```

Which should decode to the string `"Radix"`.

# Building

**Please only use a TEST DEVICE!**

**We strongly recommend using Linux as your development environment.**

## Get source
Apart from cloning, be sure you get all the submodules:
```
git submodule update --init --recursive
```

## Dependencies

#### Ledger Nano S

- This project requires Ledger firmware 1.6

- The current repository keeps track of Ledger's SDK but it is possible to override it by changing the git submodule.

#### Docker CE

- Please install [Docker](https://docs.docker.com/install/)

#### Ubuntu Dependencies
- Install the following packages:
   ```
   sudo apt update && apt-get -y install build-essential git wget cmake \
  libssl-dev libgmp-dev autoconf libtool
   ```

#### Other dependencies

- You need Python 3. In most cases, `make deps` will be able to install all additional dependencies:

   ```bash
   make deps
   ```

- You also need to install [Conan](https://conan.io/)

   ```bash
   pip install conan
   ```
   
- Before running the `make` commands below, run:

  `pip install virtualenv`
  
  `virtualenv ledger`
  
  `source ledger/bin/activate`
  
  `pip install ledgerblue`
  
- If you want to build using docker, make sure you do -not- have `BOLOS_SDK` env variable set.

> ⚠️ Some IDEs may not use the same python interpreter or virtual enviroment as the one you used when running `pip`.
If you see conan is not found, check that you installed the package in the same interpreter as the one that launches `cmake`.

# Prepare your development device

> ☣️ **Please do not use a Ledger device with funds for development purposes. Have a second device that is used ONLY for development and testing**
> ⚠️ Make sure you are **not** running Ledger HQ's desktop app _Ledger Live_ while developing, it might interfer with communication with the Ledger.

There are a few additional steps that increase reproducibility and simplify development:

**1 - Ensure your device works in your OS**
- In Linux hosts it might be necessary to adjust udev rules, etc. Refer to Ledger documentation: https://support.ledger.com/hc/en-us/articles/115005165269-Fix-connection-issues

**2 - Set a test mnemonic**

All our tests expect the device to be configured with a known test mnemonic.

- Plug your device while pressing the right button

- Your device will show "Recovery" in the screen

- Double click

- Run `make dev_init`. This will take about 2 minutes. The device will be initialized to:

   ```
   PIN: 5555
   Mnemonic: equip will roof matter pink blind book anxiety banner elbow sun young
   ```

**3 - Add a development certificate**

- Plug your device while pressing the right button

- Your device will show "Recovery" in the screen

- Click both buttons at the same time

- Enter your pin if necessary

- Run `make dev_ca`. The device will receive a development certificate to avoid constant manual confirmations.


# Building the Ledger App

The Makefile will build the firmware in a docker container and leave the binary in the correct directory.

- Build

   The following command will build the app firmware inside a container and load to your device:
   ```
   make                # Builds the app
   ```

- Upload to a device
   The following command will upload the application to the ledger. _Warning: The application will be deleted before uploading._
   ```
   make load          # Builds and loads the app to the device
   ```

# Development (building C++ Code / Tests)

This is useful when you want to make changes to libraries, run unit tests, etc. It will build all common libraries and unit tests.

## Building unit tests
While we recommend you configure your preferred development environment, the minimum steps are as follows:

   ```
   mkdir build
   cd build
   cmake .. && make
   ```
   **Run unit tests**
   ```
   export GTEST_COLOR=1 && ctest -VV
   ```

## Specifications

- [APDU Protocol](docs/APDUSPEC.md)
  - [Transaction format](docs/TXSPEC.md)
