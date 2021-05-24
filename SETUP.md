# Building

**Please only use a TEST DEVICE!**

**We strongly recommend using Linux as your development environment.**

# Prepare your development device

> ☣️ **Please do not use a Ledger device with funds for development purposes. Have a second device that is used ONLY for development and testing**
> ⚠️ Make sure you are **not** running Ledger HQ's desktop app _Ledger Live_ while developing, it might interfer with communication with the Ledger.

There are a few additional steps that increase reproducibility and simplify development:

**0 - Install Debug firmware and download USB-tool logger**
Debug print statements in the code will not be visible for you if you haven't got the debug firmware installed.

Follow Ledger's [guide here to install the Debug firmware](https://ledger.readthedocs.io/en/latest/userspace/debugging.html). 

Also make sure to download USBTool by clinking the link in the above page. ⚠️ USBTool is built for Ubuntu, but you can delete the binary from the downloaded folder and just `make` to build it to work on **macOS**. Start it with the same command `./usbtool -v 0x2c97 log`.

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

[See guide](https://ledger.readthedocs.io/en/latest/userspace/debugging.html#pin-bypass)

# Building the Ledger App

The Makefile will build the firmware in a docker container and leave the binary in the correct directory.

### Build

The following command will build the app firmware inside a container and load to your device:

```sh
make
```

### Upload to a device
The following command will upload the application to the ledger. _Warning: The application will be deleted before uploading._

```sh
make load
```