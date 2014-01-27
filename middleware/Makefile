CC = clang
CFLAGS = -shared -o $(OUT) -dynamic $(PYLIB)

PYLIB = /System/Library/Frameworks/Python.framework/Versions/2.6/Python
OUT = middleware.so

MIG = mig
MIGDEFS = mach_exc.defs
MIGCODE = mach_excUser.c mach_excServer.c
MIGHEADERS = mach_exc.h
MIGOUT = $(MIGCODE) $(MIGHEADERS)

CODE = $(MIGCODE) middleware.c middleware_py.c middleware_mach.c
HEADERS = $(MIGHEADERS) middleware.h

DEBUG = middleware.so.dSYM
DBG_FLAGS = -g


all:	$(OUT)

debug:	CFLAGS += $(DBG_FLAGS)
debug:	$(OUT) $(DEBUG)

$(OUT):	$(CODE) $(HEADERS) $(PYLIB)
	$(CC) $(CFLAGS) $(CODE)

$(MIGOUT):	$(MIGDEFS)
	$(MIG) $(MIGDEFS)

clean:
	rm -rf $(OUT) $(MIGOUT) $(DEBUG)