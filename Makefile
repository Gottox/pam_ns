LIBS=-lpam
LDFLAGS ?=
CFLAGS ?= -Wall -Werror
PREFIX ?= /usr/local

all: pam_ns.so

clean:
	rm -f pam_ns.so pam_ns.o

.c.o:
		$(CC) -c $(CFLAGS) $<

pam_ns.so: pam_ns.o
		$(LD) --shared $(LDFLAGS) -o $@ $< $(LIBS)

install: all
	install -m 0755 pam_ns.so $(DESTDIR)$(PREFIX)/lib/security

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/lib/security/pam_ns.so



.PHONY: clean install uninstall


# vim:ft=make
#
