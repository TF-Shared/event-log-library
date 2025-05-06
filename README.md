# Event Log Library (LibEvLog)

LibEvLog is a library that provides interfaces for parsing and handling TCG2
(Trusted Computing Group 2) event logs, which are generated during the pre-boot
phase of a system. These logs capture measurements of critical components and
actions by recording hash values into Platform Configuration Registers (PCRs).
Each event in the log includes metadata about the measurement, its type, and the
resulting PCR value.

Event logs play a key role in remote attestation, where a system proves its
integrity to a remote verifier. While PCR values alone are difficult to
interpret, the accompanying event log offers detailed insights into what was
measured and when. As described in the TCG specifications:

> Attestation is used to provide information about the platform’s state to a
> challenger. However, PCR contents are difficult to interpret; therefore,
> attestation is typically more useful when the PCR contents are accompanied by a
> measurement log… The PCR contents are used to provide the validation of the
> measurement log.”

libevlog makes it easier to work with these logs by providing structured access
to the data, enabling inspection, analysis, and validation of system
measurements.

## Minimum Supporting Tooling Requirements

| Tool         | Minimum Version |
| ------------ | --------------- |
| Clang-Format | 14              |
| CMake        | 3.15            |

## Building with CMake

To configure the project, use the following command. This will default to using
GCC as the toolchain and create a build directory named `build/`:

```sh
cmake -B build
```

To build the project, use:

```sh
cmake --build build
```

This will output libtl.a in the build directory.

For cross-compilation or selecting a different compiler, specify the target
compiler using `CC` or `CROSS_COMPILE`:

```sh
CC=aarch64-none-elf-gcc cmake -B build -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY
```

## Configuration Options

### `HASH_ALGORITHM`

This CMake option controls which hash algorithm the library is compiled to
support. Currently, the library is designed to support **only a single algorithm
at a time**, chosen at compile time. The selection sets corresponding
preprocessor definitions, which configure internal behavior for digest size and
algorithm identifiers.

| `HASH_ALGORITHM` | Defined Macro(s)                                             |
|------------------|--------------------------------------------------------------|
| `SHA512`         | `TPM_ALG_ID=TPM_ALG_SHA512`, `TCG_DIGEST_SIZE=64U`           |
| `SHA324`         | `TPM_ALG_ID=TPM_ALG_SHA384`, `TCG_DIGEST_SIZE=48U`           |
| _(default)_      | `TPM_ALG_ID=TPM_ALG_SHA256`, `TCG_DIGEST_SIZE=32U`           |

These macros configure the internal logic of the library for the specified hash
function.

> **Note:** The current implementation only supports compiling with a single
algorithm. However, the long-term goal is to allow users to specify and use
**multiple hash functions** within the same build. This will enable more
flexible and dynamic cryptographic functionality.

### Example Usage

**To build the library with SHA384 support:**

```bash
cmake -DHASH_ALGORITHM=SHA324 ..
make
```

**To build the library with default SHA256:**

```bash
cmake ..
make
```
