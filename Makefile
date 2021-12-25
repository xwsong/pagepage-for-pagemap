TARGETS=pagepage

CFLAGS = -Wall -Wextra

all: $(TARGETS)

pagepage: pagemap.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

clean:
	rm pagepage

sbindir ?= /usr/sbin

install: all 
	install -d $(DESTDIR)$(sbindir)
	install -m 755 -p $(TARGETS) $(DESTDIR)$(sbindir)

