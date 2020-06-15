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

### SIGN ATOM

You can try the sign atom action using the small Python script [`sign_example_atom.py`](sign_example_atom.py)

To try signing a small atom you can just run

```sh
python sign_example_atom.py
```

Which will default to a smaller simpler atom.

If you wanna test specific atom, you can select a specific atom with `--inputAtomVector` (or `--i` for short)

```sh
python sign_example_atom.py --i vectors/data_no_transfer_burn_action.json
```

Have a look


You can also run test all atoms with the command:

```sh
python sign_example_atom.py --all
```
