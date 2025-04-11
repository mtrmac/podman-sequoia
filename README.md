# podman-sequoia

podman-sequoia enables to use [sequoia-pgp] as an OpenPGP backend in
the podman's image signing [mechanism]. It consists of a C shared
library (in `rust/`) and a Go binding over it (in `go/`).

## Building

To build, you need rustc (version 1.63 or later), cargo, and
openssl-devel.

The following steps should be taken to build the binaries locally.

```console
$ cd rust
$ PREFIX=/usr LIBDIR="\${prefix}/lib64" \
  cargo build --release
$ cd -
```

```console
$ cd go/sequoia
$ CGO_CFLAGS=-I$PWD/../../rust/target/release/bindings \
  CGO_LDFLAGS=-L$PWD/../../rust/target/release \
  go build
$ LD_LIBRARY_PATH=$PWD/../../rust/target/release \
  CGO_CFLAGS=-I$PWD/../../rust/target/release/bindings \
  CGO_LDFLAGS=-L$PWD/../../rust/target/release \
  go test
$ cd -
```

## Installing

To actually make the Go sequoia module useful, the
`libpodman_sequoia.so*` shared library needs to be installed on the
system.

```console
$ sudo cp -a rust/target/release/libpodman_sequoia.so* /usr/lib64
```

## License

LGPL-2.0-or-later

[sequoia-pgp]: https://sequoia-pgp.org/
[mechanism]: https://pkg.go.dev/github.com/containers/image/v5@v5.30.0/signature#SigningMechanism
