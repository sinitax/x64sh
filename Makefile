PREFIX ?= /usr/local
BINDIR ?= /bin

CFLAGS = -I lib/bestline/ -I src \
		-I lib/xed/include/public -I lib/xed/include/public/xed \
		-I lib/xed/examples -I lib/xed/obj -L lib/xed/obj
CFLAGS_WARN = -Wunused-variable -Wunused-function -Wconversion
LDLIBS = -lxed

XED_EXAMPLE_O = lib/xed/examples/obj/xed-examples-util.o \
		lib/xed/examples/obj/xed-dot-prep.o \
		lib/xed/examples/obj/xed-dot.o

all: build/x64sh

lib/xed/mfile.py:
	git submodule update --init lib/xed

lib/bestline/Makefile:
	git submodule update --init lib/bestline

tools/mbuild/setup.py:
	git submodule update --init tools/mbuild

venv: tools/mbuild/setup.py | tools/mbuild/setup.py
	python3 -m virtualenv venv
	source venv/bin/activate && python3 -m pip install -e tools/mbuild

lib/xed/lib: | lib/xed/mfile.py
	ln -sf obj lib/xed/lib

lib/xed/obj/libxed.a: | venv
	source venv/bin/activate && cd lib/xed && python3 mfile.py

$(XED_EXAMPLE_O): lib/xed/obj/libxed.a | venv lib/xed/lib
	rm -f $(XED_EXAMPLE_O)
	source venv/bin/activate && cd lib/xed/examples && python3 mfile.py

lib/bestline/bestline.o: lib/bestline/Makefile
	make -C lib/bestline bestline.o

build:
	mkdir build

build/xed-asmparse-main.o: src/xed-asmparse-main.c | $(XED_EXAMPLE_O) build
	$(CC) -c -o $@ $^ $(CFLAGS)

build/xed-asmparse.o: src/xed-asmparse.c | $(XED_EXAMPLE_O) build
	$(CC) -c -o $@ $^ $(CFLAGS)

build/x64sh: src/x64sh.c build/xed-asmparse-main.o build/xed-asmparse.o \
		lib/bestline/bestline.o $(XED_EXAMPLE_O) | build
	$(CC) -o $@ $^ -static $(CFLAGS) $(CFLAGS_WARN) $(LDLIBS)

clean:
	rm -rf build

cleanall: clean
	make -C lib/bestline clean
	source venv/bin/activate && cd lib/xed && python3 mfile.py clean
	source venv/bin/activate && cd lib/xed/examples && python3 mfile.py clean
	rm -rf venv

install:
	install -d "$(DESTDIR)$(PREFIX)$(BINDIR)"
	install -m 755 x64sh -t "$(DESTDIR)$(PREFIX)$(BINDIR)"

uninstall:
	rm -rf "$(DESTDIR)$(PREFIX)$(BINDIR)/x64sh"

.PHONY: all clean cleanall install uninstall
