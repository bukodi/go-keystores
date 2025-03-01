# `pkcs11ks` package

Provides a simple key store implementation for PKCS#11 tokens.

## Object model
The P11Provider represents one or more PKCS#11 library with library configuration.
On Open() the P11Provider tries to load the PKCS#11 libraries and initializes them, as a result the internal keyStore list will be populated with unopened P11KeyStore instances.
On Close() the P11Provider closes the P11KeyStore objects and finalizes the PKCS#11 libraries.

The P11Provider is a singleton, the singleton instance can be accessed by the `Instance()` function.


## Usage

```go

