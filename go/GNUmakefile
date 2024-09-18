# SPDX-License-Identifier: LGPL-2.0-or-later

srcdir = .
abs_srcdir = $(shell realpath $(srcdir))

RELEASE ?= 0
ifeq ($(RELEASE),1)
        PROFILE ?= release
else
        PROFILE ?= debug
endif

all:: stamp_c_files

podman_openpgp_h = \
	../rust/target/${PROFILE}/include/podman/openpgp.h
dlwrap_files = \
	../rust/target/${PROFILE}/include/goopenpgp.c \
	../rust/target/${PROFILE}/include/goopenpgp.h \
	../rust/target/${PROFILE}/include/goopenpgpfuncs.h

$(c_files): stamp_c_files
stamp_c_files:
	mkdir -p sequoia/include/podman && \
	cp $(podman_openpgp_h) sequoia/include/podman && \
	cp $(dlwrap_files) sequoia && \
	touch $@

maintainer-clean::
	rm -f $(podman_openpgp_h)
	rm -f $(dlwrap_files)
	rm -f stamp_c_files
