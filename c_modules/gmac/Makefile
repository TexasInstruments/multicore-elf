include ../../imports.mak

COMPILER_MACHINE:=$(shell $(COMPILER_PATH) -dumpmachine)

CFLAGS= \
	-fPIC \
	-shared\
	-Wall \
	-Werror \

DEPS= \

ODIR=dist

SRCFILE=gmac.c

SHARED_LIB_NAME=gmac.$(COMPILER_MACHINE).$(OS_NAME).$(SHARED_LIB_EXT)

all:
	$(COMPILER_PATH) -o $(ODIR)/$(SHARED_LIB_NAME) $(SRCFILE) $(CFLAGS)

.PHONY: clean

clean:
	rm -f $(ODIR)/*.$(SHARED_LIB_EXT)