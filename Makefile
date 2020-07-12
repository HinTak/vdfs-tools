#
# Makefile for the linux vdfs4-filesystem tools routines.
#
##########################################################################
# VDFS Tools Version Definition(MAJ.MIN-DATE)
##########################################################################
#-------------------------------------------------------------------------
MAJ_VER=1
MIN_VER=43
DATE=191204 #YYMMDD
#-------------------------------------------------------------------------
TOOLS_VERSION="$(strip $(MAJ_VER)).$(strip $(MIN_VER))-$(strip $(DATE))"
##########################################################################

MKFS = mkfs.vdfs
UNPACK = unpack.vdfs
FSCK = fsck.vdfs
TUNE = tune.vdfs
PAGE_TYPES = page-types.vdfs
TEST = test
BTREE_TEST = btrtst
INFO = info.vdfs

UNITTEST = unit_tests_cunit
CC = $(CROSS_COMPILE)gcc
HOST=`$(CROSS_COMPILE)gcc -dumpmachine`
LIBS = -lrt -lpthread
LIBZ = -lz

OPENSSL_BASE=./openssl
OPENSSL_DIR=$(OPENSSL_BASE)/openssl-1.0.1g
OPENSSL_LIB=-L$(OPENSSL_DIR) -lcrypto -ldl
OPENSSL_PACK=$(OPENSSL_BASE)/openssl-1.0.1g.tar.gz

CFLAGS += -Wall -Wextra -I./include -I./key
CFLAGS += -DTOOLS_VERSION=\"$(TOOLS_VERSION)\"
CFLAGS += -O1 -ggdb -MD
CFLAGS += -DUSER_SPACE
CFLAGS += -DCONFIG_VDFS4_DEBUG
CFLAGS += -Iinclude
CFLAGS += -D_FILE_OFFSET_BITS=64

ifdef VDFS4_NO_WARN
	CFLAGS += -Werror
endif

ifeq ($(host),x86_32)
	CROSS_COMPILE=
	HOST=i686-linux-gnu
	CFLAGS += -m32
	SECURE_CFLAGS += -m32
endif
ifeq ($(host),x86_64)
	CROSS_COMPILE=
	HOST=x86_64-linux-gnu
endif

CFLAGS += -I$(OPENSSL_DIR)/include

#Secure flags
ifeq ($(ENABLE_SECURE_FLAGS),1)
 SECURE_CFLAGS += -fstack-protector-strong
 SECURE_CFLAGS += -Wl,-z,relro
 SECURE_CFLAGS += -D_FORTIFY_SOURCE=2 -O1
 SECURE_CFLAGS += -fPIE -pie
 CFLAGS += $(SECURE_CFLAGS)
endif

SOURCE_MKFS = $(wildcard ./mkfs/*.c)
SOURCE_UNPACK = $(wildcard ./unpack/*.c)
SOURCE_FSCK = $(wildcard ./fsck/*.c)
SOURCE_TEST = $(wildcard ./full_btree_test/*.c)
SOURCE_BTREE_TEST = $(wildcard ./btree_test/*.c)
SOURCE_TUNE = $(wildcard ./tune/*.c)
SOURCE_LIB = $(wildcard ./lib/*.c)
SOURCE_PAGE_TYPES = $(wildcard ./vm/*.c)
SOURCE_INFO = $(wildcard ./info/*.c)
SOURCE_KEY = $(wildcard ./key/*.c)


DEPS = $(wildcard ./mkfs/*.d)
DEPS := $(DEPS) $(wildcard ./unpack/*.d)
DEPS := $(DEPS) $(wildcard ./fsck/*.d)
DEPS := $(DEPS) $(wildcard ./full_btree_test/*.d)
DEPS := $(DEPS) $(wildcard ./tune/*.d)
DEPS := $(DEPS) $(wildcard ./lib/*.d)
DEPS := $(DEPS) $(wildcard ./btree_test/*.d)
DEPS := $(DEPS) $(wildcard ./info/*.d)

DEPS := $(DEPS) $(wildcard ./tune/*.d)
DEPS := $(DEPS) $(wildcard ./lib/*.d)
DEPS := $(DEPS) $(wildcard ./vm/*.d)
DEPS := $(DEPS) $(wildcard ./unit_tests_cunit/*.d)
DEPS := $(DEPS) $(wildcard ./unit_tests_cunit/mkfs/*.d)


ZLIB_BASE = ./zlib

ZLIB_ARCH = $(wildcard $(ZLIB_BASE)/zlib*.tar.gz)
ZLIB_DIR = $(ZLIB_ARCH:.tar.gz=)
ZLIB_FILE = $(ZLIB_DIR)/libz.a
CFLAGS += -I$(ZLIB_DIR)
LZOLIB_BASE = ./lzolib
LZOLIB_ARCH = $(wildcard $(LZOLIB_BASE)/lzo*.tar.gz)
LZOLIB_DIR = $(LZOLIB_ARCH:.tar.gz=)
LZOLIB_FILE = $(LZOLIB_DIR)/src/.libs/liblzo2.a
CFLAGS += -I$(LZOLIB_DIR)/include
CFLAGS += -I$(HOME)/local/include

OBJ_MKFS = $(SOURCE_MKFS:.c=.o)
OBJ_TUNE = $(SOURCE_TUNE:.c=.o)
OBJ_LIB = $(SOURCE_LIB:.c=.o)
OBJ_FSCK = $(SOURCE_FSCK:.c=.o)
OBJ_TEST = $(SOURCE_TEST:.c=.o)
OBJ_BTREE_TEST = $(SOURCE_BTREE_TEST:.c=.o)
OBJ_UNPACK = $(SOURCE_UNPACK:.c=.o)
OBJ_MKFS_UNIT = $(SOURCE_MKFS_UNIT:.c=.o)
OBJ_LIB_UNIT = $(SOURCE_LIB_UNIT:.c=.o)
OBJ_UNPACK_UNIT = $(SOURCE_UNPACK_UNIT:.c=.o)
OBJ_TUNE_UNIT = $(SOURCE_TUNE_UNIT:.c=.o)
OBJ_INFO = $(SOURCE_INFO:.c=.o)
OBJ_KEY = $(SOURCE_KEY:.c=.o)

unpack: CFLAGS += -D__RD_FROM_VOL__
fsck: CFLAGS += -D__RD_FROM_VOL__
btrtst: CFLAGS += -DCONFIG_VDFS4_DEBUG_TOOLS_GET_BNODE

all: mkfs unpack tune fsck info

openssl: $(OPENSSL_PACK)
	@if [ ! -d $(OPENSSL_DIR) ]; then tar -xf $(OPENSSL_PACK) -C $(OPENSSL_BASE); cd $(OPENSSL_DIR); ./Configure no-shared no-asm linux-elf --cross-compile-prefix=$(CROSS_COMPILE) $(SECURE_CFLAGS); make build_crypto; fi

zlib: $(ZLIB_ARCH)
	@if [ ! -d $(ZLIB_DIR) ]; then tar -xf $(ZLIB_ARCH) -C $(ZLIB_BASE); cd $(ZLIB_DIR); env CC=$(CROSS_COMPILE)gcc CFLAGS="$(SECURE_CFLAGS)" ./configure; make; fi

lzo: $(LZO_ARCH)
	@if [ ! -d $(LZOLIB_DIR) ]; then tar -xf $(LZOLIB_ARCH) -C $(LZOLIB_BASE); cd $(LZOLIB_DIR); env CFLAGS="$(SECURE_CFLAGS)" ./configure --host=$(HOST) --target=$(HOST) -q; make src/liblzo2.la; fi

mkfs: lzo zlib openssl $(OBJ_LIB) $(OBJ_MKFS) $(OBJ_KEY)
	@$(CC) -g -rdynamic -std=gnu99 -o $(MKFS) $(OBJ_LIB) $(OBJ_MKFS) $(OBJ_KEY) $(LIBS) $(ZLIB_FILE) $(LZOLIB_FILE) $(OPENSSL_LIB) $(SECURE_CFLAGS) $(CFLAGS)
	@echo "  CCLD      " $@;

unpack: zlib lzo openssl $(OBJ_LIB) $(OBJ_UNPACK)
	@$(CC) -o $(UNPACK) $(OBJ_LIB) $(OBJ_UNPACK) $(LIBS) $(ZLIB_FILE) $(LZOLIB_FILE) $(OPENSSL_LIB) $(CFLAGS)
	@echo "  CCLD      " $@;

test: lzo zlib openssl $(OBJ_LIB) $(OBJ_TEST)
	@$(CC) -o $(TEST) $(OBJ_LIB) $(OBJ_TEST) $(ZLIB_FILE) $(LZOLIB_FILE) $(OPENSSL_LIB) $(CFLAGS)
	@echo "  CCLD      " $@;

btrtst: lzo zlib openssl $(OBJ_LIB) $(OBJ_BTREE_TEST)
	@$(CC) -o $(BTREE_TEST) $(OBJ_LIB) $(OBJ_BTREE_TEST) $(ZLIB_FILE) $(LZOLIB_FILE) $(OPENSSL_LIB) $(CFLAGS)
	@echo "  CCLD      " $@;

tune: lzo zlib openssl $(OBJ_LIB) $(OBJ_TUNE)
	@$(CC) -std=gnu99 -o $(TUNE) $(OBJ_LIB) $(OBJ_TUNE) $(LIBS) $(ZLIB_FILE) $(LZOLIB_FILE) $(OPENSSL_LIB) $(CFLAGS)
	@echo "  CCLD      " $@;

fsck: zlib lzo openssl $(OBJ_LIB) $(OBJ_FSCK)
	@$(CC) -std=gnu99 -o $(FSCK) $(OBJ_LIB) $(OBJ_FSCK) $(LIBS) $(ZLIB_FILE) $(LZOLIB_FILE) -lm $(OPENSSL_LIB) $(CFLAGS)
	@echo "  CCLD      " $@;

page-types: $(OBJ_PAGE_TYPES)
	@$(CC) -std=gnu99 -o $(PAGE_TYPES) $(OBJ_PAGE_TYPES) $(CFLAGS)
	@echo "  CCLD      " $@;

info: openssl $(OBJ_INFO)
	@$(CC) -std=gnu99 -o $(INFO) $(OBJ_INFO) $(CFLAGS)
	@echo "  CCLD      " $@;
%.o : %.c
	@$(CC) $(CFLAGS) -c $< -o $@
	@echo "  CC        " $@;
-include $(DEPS)

#%.P: %.c
	#$(CC) -std=gnu99 -MM $(OBJ_LIB) $(OBJ_MKFS) $(LIBS)
clean:
	-rm -f $(OBJ_LIB)
	-rm -f $(MKFS) $(OBJ_MKFS)
	-rm -f $(UNPACK) $(OBJ_UNPACK)
	-rm -f $(FSCK) $(OBJ_FSCK)
	-rm -f $(TUNE) $(OBJ_TUNE)
	-rm -f $(TEST) $(OBJ_TEST)
	-rm -f $(PAGE_TYPES) $(OBJ_PAGE_TYPES)
	-rm -f $(INFO) $(OBJ_INFO)
	-rm -f $(OBJ_KEY)
	-rm -rf *.o
	-rm -rf ./src/*.o
	-rm -f $(UNITTEST)/*.o
	-rm -f $(DEPS)
	$(shell rm -f `find -name \*.o` > /dev/null 2> /dev/null)
	$(shell rm -f `find -name \*.d` > /dev/null 2> /dev/null)
	$(shell rm -f `find -name test` > /dev/null 2> /dev/null)
	$(shell rm -f `find -name \*.gcno` > /dev/null 2> /dev/null)
	$(shell rm -f `find -name \*.gcda` > /dev/null 2> /dev/null)
	$(shell rm -f `find -name \*.gcov` > /dev/null 2> /dev/null)
	$(shell rm -f `find -name test_report` > /dev/null 2> /dev/null)

distclean: clean
	-rm -rf $(ZLIB_DIR)
	-rm -rf $(LZOLIB_DIR)
	-rm -rf $(OPENSSL_DIR)

opensource: clean
	-rm -rf ./fsck ./info ./vdcrc ./tune ./unpack

unit_tests:
	$(eval export CFLAGS = -fprofile-arcs -ftest-coverage $(CFLAGS))
	$(eval export LFLAGS = -lgcov -coverage $(LFLAGS))
	make unit_tests_internal

unit_tests_internal: lzo zlib openssl $(OBJ_LIB) $(OBJ_MKFS) $(OBJ_TUNE) $(OBJ_UNPACK)
	$(eval export CURRENT_DIRECTORY = $(shell pwd))
	$(eval export CFLAGS = -I$(CURRENT_DIRECTORY)/include $(CFLAGS))
	$(eval export CC HOME LIBS OPENSSL_LIB CPPFLAGS TARGET_ARCH)
	$(eval export OBJ_LIB = $(foreach lib,$(OBJ_LIB),$(CURRENT_DIRECTORY)/$(lib)))
	$(eval export OBJ_MKFS = $(foreach lib,$(OBJ_MKFS),$(CURRENT_DIRECTORY)/$(lib)))
	$(eval export OBJ_UNPACK = $(foreach lib,$(OBJ_UNPACK),$(CURRENT_DIRECTORY)/$(lib)))
	$(eval export OBJ_TUNE = $(foreach lib,$(OBJ_TUNE),$(CURRENT_DIRECTORY)/$(lib)))
	$(eval export ZLIB_FILE = $(foreach lib,$(ZLIB_FILE),$(CURRENT_DIRECTORY)/$(lib)))
	$(eval export LZOLIB_FILE = $(foreach lib,$(LZOLIB_FILE),$(CURRENT_DIRECTORY)/$(lib)))
	$(eval export OPENSSL_LIB = $(subst -L./,-L$(CURRENT_DIRECTORY)/,$(OPENSSL_LIB)))
	strip --strip-symbol main $(OBJ_MKFS);
	strip --strip-symbol main $(OBJ_TUNE);
	strip --strip-symbol main $(OBJ_UNPACK);
	make -C unit_tests_cunit
	$(UNITTEST)/count_results.sh
	gcov $(SOURCE_MKFS) $(SOURCE_UNPACK)  $(SOURCE_TEST) $(SOURCE_BTREE_TEST) $(SOURCE_TUNE)  $(SOURCE_LIB)

.PHONY: all zlib clean mkfs unpack tune fsck openssl lzo info
