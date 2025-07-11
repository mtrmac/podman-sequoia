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

c_files = \
	../target/${PROFILE}/bindings/sequoia.h \
	../target/${PROFILE}/bindings/gosequoia.c \
	../target/${PROFILE}/bindings/gosequoia.h \
	../target/${PROFILE}/bindings/gosequoiafuncs.h

$(c_files): stamp_c_files
stamp_c_files:
	cp $(c_files) sequoia && \
	touch $@

maintainer-clean::
	rm -f $(c_files) stamp_c_files
