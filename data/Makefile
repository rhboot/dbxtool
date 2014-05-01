SRCDIR = .
TOPDIR = $(SRCDIR)/..

include $(TOPDIR)/Make.defaults

all :

deps :

depclean :

clean :

install :
	$(INSTALL) -d -m 755 $(INSTALLROOT)$(PREFIX)/share/dbxtool/
	for x in *.bin ; do \
		$(INSTALL) -m 644 $$x $(INSTALLROOT)$(PREFIX)/share/dbxtool/ ;\
	done

.PHONY: all deps clean depclean install

include $(TOPDIR)/Make.rules
