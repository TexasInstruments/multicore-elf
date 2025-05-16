ifeq ($(OS),Windows_NT)
    RMDIR=$(CYGWIN_PATH)/rm -rf
    RM=$(CYGWIN_PATH)/rm -f
    COMPILER_PATH=gcc.exe
    SHARED_LIB_EXT=dll
    OS_NAME=win32
else
    UNAME_S := $(shell uname -s)
    ifneq (,$(filter $(UNAME_S),Linux))
        export RMDIR=rm -rf
        export RM=rm -f
        export COMPILER_PATH=gcc
        export SHARED_LIB_EXT=so
        export OS_NAME=linux
    endif
    ifneq (,$(filter $(UNAME_S),Darwin))
        export RMDIR=rm -rf
        export RM=rm -f
        export COMPILER_PATH=gcc
        export SHARED_LIB_EXT=dylib
        export OS_NAME=darwin
    endif
endif


