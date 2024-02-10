# OpenSSL

**tl;dr: the libraries in this package require OpenSSL v3.x.**

In line with [OpenSSL's release strategy][0], we aim to support the latest
release of any LTS or non-LTS version of OpenSSL which is currently receiving
public bugfix support from the OpenSSL project.

We do not support any version of OpenSSL which:

* is not supported by the `openssl` Rust crate
* is not supported by the OpenSSL project at all
* has less than one year of support remaining (ie: no "bugfix support")
* is only supported with a [paid support contract][1] (aka: "extended support")
* has been superseded by a newer upstream release

This includes versions of OpenSSL shipped as part of "stable" Linux
distributions, even if the distributor is maintaining them. Unfortunately,
tracking and managing these is very complicated and time consuming.

This is subject to change as [OpenSSL's release strategy][0] evolves, or if we
encounter bugs or limitations with particular versions of OpenSSL.

As of `openssl` crate version 0.10.56, the `vendored` feature on the `openssl` crate uses OpenSSL v3, thus using the `vendored` flag is a option. However, it's worth considering whether vendored OpenSSL is the right approach for your project, as can make updating in the case of OpenSSL vulnerabilities harder, and upstream packagers may not support it.

[0]: https://www.openssl.org/policies/releasestrat.html
[1]: https://www.openssl.org/support/contracts.html

## Linux

Install `libssl-dev`, `openssl-dev` and/or `openssl-devel` from your package
manager. As long as you have OpenSSL v3.x, this should _Just Work_™.

## macOS

Install `openssl` from `brew`. Everything should _Just Work_®.

## Windows

### MSVC (recommended)

Install `vcpkg`, and set the `VCPKG_ROOT` environment variable to the path where
you checked out `vcpkg` (eg: `c:\src\vcpkg`).

Then, build OpenSSL from source using `vcpkg`:

```powershell
# This builds and installs both x64 and arm64 versions of OpenSSL; you only need
# to install both if building for both architectures.
vcpkg install openssl:x64-windows-static-md openssl:arm64-windows-static-md
```

`openssl-sys` should automatically detect this installation, and you should be
able to cross-compile for `aarch64-pc-windows-msvc` and `x86_64-pc-windows-msvc`
from either an `arm64` or `x86_64` system.

### MSYS2

**Note:** MSYS2's version of Rust does not support cross-compiling, and its
version of OpenSSL does not support static linking.

**Warning:** building on ARM64 is [broken due to a bug in `windows-rs`][5] which
is not fixed in any stable release of the package.

[5]: https://github.com/microsoft/windows-rs/pull/2515

**TODO:** test ARM64 instructions.

Install pkgconfig, OpenSSL and Rust with `pacman`:

```sh
# On x86_64
pacman -S pkg-config openssl-devel mingw-w64-clang-x86_64-openssl mingw-w64-clang-x86_64-rust mingw-w64-clang-x86_64-toolchain
# On arm64
pacman -S pkg-config openssl-devel mingw-w64-clang-aarch64-openssl mingw-w64-clang-aarch64-rust mingw-w64-clang-aarch64-toolchain
```

You'll need to set some extra environment variables:

```sh
export PKG_CONFIG_PATH=$MSYSTEM_PREFIX/lib/pkgconfig/
# only on x86_64:
export CC=clang
```

You should then be able to build tools with `cargo`, eg:

```sh
cargo build --release -p fido-key-manager
cp $MSYSTEM_PREFIX/bin/libcrypto-3*.dll target/release/
cp $MSYSTEM_PREFIX/bin/libssl-3*.dll target/release/
```

### Cross-compiled from non-Windows

**Note:** this currently only targets `x86_64`. There is an
[`aarch64-pc-windows-gnullvm` target][2], but this is currently only Tier 3.

**Work in progress:** this is currently blocked on [`vcpkg-rs` supporting
`-pc-windows-gnu` targets][3] or [`openssl-sys` supporting `pkgconfig` for
Windows targets from non-Windows hosts][4].

[2]: https://doc.rust-lang.org/rustc/platform-support/pc-windows-gnullvm.html
[3]: https://github.com/mcgoo/vcpkg-rs/pull/52
[4]: https://github.com/sfackler/rust-openssl/issues/1984

Install `vcpkg` and an appropriate `mingw` toolchain.

Add these environment variables to `~/.bashrc` or `~/.zshenv`:

```sh
# the location where you checked out vcpkg to
export VCPKG_ROOT="$HOME/vcpkg"
export PKG_CONFIG_PATH_x86_64_pc_windows_gnu="$VCPKG_ROOT/installed/x64-mingw-static/lib/pkgconfig" 

vcpkg install openssl:x64-mingw-static
```

You should then be able to build tools with `cargo`, eg:

```sh
cargo build --target x86_64-pc-windows-gnu -p fido-key-manager
```
