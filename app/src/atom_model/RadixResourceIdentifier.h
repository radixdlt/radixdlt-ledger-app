/* A Radix resource identifier is a human readable index into the Ledger which points to a name state machine */
typedef struct {
    /* On format: `/:address/:name`, e.g.: `"/JH1P8f3znbyrDj8F4RWpix7hRkgxqHjdW2fNnKpR3v6ufXnknor/XRD"` */
    char *identifier; // 39 (address) + 1 (slash) + 1-14 (Symbol) bytes, but we support unlimited length
} RadixResourceIdentifier;
