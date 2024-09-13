# SPDX-License-Identifier: LGPL-2.0-or-later

srcdir = .
abs_srcdir = $(shell realpath $(srcdir))
DLWRAP = dlwrap

RELEASE ?= 0
ifeq ($(RELEASE),1)
        PROFILE ?= release
else
        PROFILE ?= debug
endif

c_files = sequoia/goopenpgp.h sequoia/goopenpgp.c sequoia/goopenpgpfuncs.h

all:: $(c_files)

podman_openpgp_h = ../rust/target/${PROFILE}/include/podman/openpgp.h

$(c_files): $(podman_openpgp_h)
	$(DLWRAP) --input $(podman_openpgp_h) -o . \
		--clang-resource-dir "$(shell clang -print-resource-dir)" \
		--symbol-regex "^openpgp_" \
		--license "SPDX-License-Identifier: LGPL-2.0-or-later" \
		--loader-basename goopenpgp \
		--soname OPENPGP_SONAME \
		--prefix go_openpgp \
		--function-prefix go \
		--header-guard GO_OPENPGP_H_ \
		--include "<podman/openpgp.h>"

clean::
	rm -f $(c_files)
