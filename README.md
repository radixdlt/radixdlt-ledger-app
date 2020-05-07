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

Should result in this BIP path: `44'/536'/2'/1/3`. And using the mnemonic mentioned below (`equip will roof....`), ought to result in this compressed public key `026d5e07cfde5df84b5ef884b629d28d15b0f6c66be229680699767cd57c618288` and private key: `f423ae3097703022b86b87c15424367ce827d11676fae5c7fe768de52d9cce2e`

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

#### 253 chars long string is max
Since we need 2 bytes to CBOR encode a string, resulting in 253+2 = 255 bytes, which is `FF` in hex, which is max value that fit in the single byte, parameter `L` according to APDU spec, describing the lenght of the payload, that is the max string we can send. 

##### 249 bytes
This long Lorem ipsum text works.

`"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Etiam sollicitudin porttitor odio eu laoreet. Ut dui lacus, accumsan a orci a, pretium suscipit velit. Sed quis dignissim arcu. In a magna sit amet quam malesuada consectetur vel vitae tortor non."` 
(253 chars)

Resulting in APDU:

```sh
echo 'AA020000ff78FD4C6F72656D20697073756D20646F6C6F722073697420616D65742C20636F6E73656374657475722061646970697363696E6720656C69742E20457469616D20736F6C6C696369747564696E20706F72747469746F72206F64696F206575206C616F726565742E20557420647569206C616375732C20616363756D73616E2061206F72636920612C207072657469756D2073757363697069742076656C69742E205365642071756973206469676E697373696D20617263752E20496E2061206D61676E612073697420616D6574207175616D206D616C65737561646120636F6E73656374657475722076656C20766974616520746F72746F72206E6F6E2E' | python -m ledgerblue.runScript --targetId 0x31100004 --apdu
```

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
