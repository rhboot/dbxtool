SRCDIR = .
TOPDIR = $(SRCDIR)/..

include $(TOPDIR)/Make.defaults

PKLIBS = nss efivar
LIBS = popt
STATIC_LIBS = 
LDFLAGS =
CCLDFLAGS = $(foreach pklib,$(PKLIBS), $(shell pkg-config --libs-only-L $(pklib)))
BUILDFLAGS += $(foreach pklib,$(PKLIBS), $(shell pkg-config --cflags $(pklib))) -Werror

TARGETS = dbxtool

all : $(TARGETS)

dbxtool_SOURCES = dbxtool.c iter.c
dbxtool_OBJECTS = $(foreach source,$(dbxtool_SOURCES),$(patsubst %.c,%,$(source)).o)
dbxtool_DEPS = $(foreach source,$(dbxtool_SOURCES),.$(patsubst %.c,%,$(source)).P)
dbxtool : $(dbxtool_OBJECTS) $(STATIC_LIBS)

DEPS = $(dbxtool_DEPS)

deps : $(DEPS)

depclean :
	@rm -fv .*.P

-include $(DEPS)

clean : depclean
	@rm -rfv *.o *.a *.so $(TARGETS)

install :
	$(INSTALL) -d -m 755 $(INSTALLROOT)$(PREFIX)/bin/
	$(INSTALL) -m 755 dbxtool $(INSTALLROOT)$(PREFIX)/bin/

.PHONY: all deps clean depclean install

include $(TOPDIR)/Make.rules
