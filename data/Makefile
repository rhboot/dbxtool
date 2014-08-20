SRCDIR = .
TOPDIR = $(SRCDIR)/..

include $(TOPDIR)/Make.defaults

all :

deps :

depclean :

clean :

install :
	$(INSTALL) -d -m 755 $(INSTALLROOT)$(PREFIX)/share/dbxtool/
	$(INSTALL) -m 644 $$(ls -1 DBXUpdate*.bin | sort -n | tail -1) \
		$(INSTALLROOT)$(PREFIX)/share/dbxtool/

.PHONY: all deps clean depclean install

include $(TOPDIR)/Make.rules
