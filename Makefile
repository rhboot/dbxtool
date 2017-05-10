TOPDIR = $(shell echo $$PWD)

include $(TOPDIR)/Make.version
include $(TOPDIR)/Make.rules
include $(TOPDIR)/Make.defaults

SUBDIRS := src data
DOCDIR := /share/doc/

all : $(SUBDIRS)

include $(TOPDIR)/Make.coverity

$(SUBDIRS) :
	$(MAKE) -C $@ TOPDIR=$(TOPDIR) SRCDIR=$(TOPDIR)/$@/

clean :
	@for x in $(SUBDIRS) ; do $(MAKE) -C $${x} TOPDIR=$(TOPDIR) SRCDIR=$(TOPDIR)/$@/ $@ ; done

install :
	@for x in $(SUBDIRS) ; do $(MAKE) -C $${x} TOPDIR=$(TOPDIR) SRCDIR=$(TOPDIR)/$@/ $@ ; done
	$(INSTALL) -d -m 755 $(INSTALLROOT)$(PREFIX)$(DOCDIR)/dbxtool/
	$(INSTALL) -m 644 COPYING $(INSTALLROOT)$(PREFIX)$(DOCDIR)/dbxtool/

.PHONY: $(SUBDIRS) clean install

GITTAG = $(VERSION)

test-archive:
	@rm -rf /tmp/dbxtool-$(VERSION) /tmp/dbxtool-$(VERSION)-tmp
	@mkdir -p /tmp/dbxtool-$(VERSION)-tmp
	@git archive --format=tar $(shell git branch | awk '/^*/ { print $$2 }') | ( cd /tmp/dbxtool-$(VERSION)-tmp/ ; tar x )
	@git diff | ( cd /tmp/dbxtool-$(VERSION)-tmp/ ; patch -s -p1 -b -z .gitdiff )
	@mv /tmp/dbxtool-$(VERSION)-tmp/ /tmp/dbxtool-$(VERSION)/
	@dir=$$PWD; cd /tmp; tar -c --bzip2 -f $$dir/dbxtool-$(VERSION).tar.bz2 dbxtool-$(VERSION)
	@rm -rf /tmp/dbxtool-$(VERSION)
	@echo "The archive is in dbxtool-$(VERSION).tar.bz2"

tag:
	git tag -s dbxtool-$(GITTAG) refs/heads/master

archive: tag
	@rm -rf /tmp/dbxtool-$(VERSION) /tmp/dbxtool-$(VERSION)-tmp
	@mkdir -p /tmp/dbxtool-$(VERSION)-tmp
	@git archive --format=tar dbxtool-$(GITTAG) | ( cd /tmp/dbxtool-$(VERSION)-tmp/ ; tar x )
	@mv /tmp/dbxtool-$(VERSION)-tmp/ /tmp/dbxtool-$(VERSION)/
	@dir=$$PWD; cd /tmp; tar -c --bzip2 -f $$dir/dbxtool-$(VERSION).tar.bz2 dbxtool-$(VERSION)
	@rm -rf /tmp/dbxtool-$(VERSION)
	@echo "The archive is in dbxtool-$(VERSION).tar.bz2"
