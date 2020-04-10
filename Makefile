
PKG_CONFIG ?= pkg-config

CFLAGS	?= -O2 -g -pipe -Wno-deprecated-declarations
LDFLAGS ?= 

# Windoze support is not needed, because I can!
INCLUDES = 
CC ?= gcc

ifeq ($(shell $(PKG_CONFIG) --exists purple-3 2>/dev/null && echo "true"),)
  ifeq ($(shell $(PKG_CONFIG) --exists purple 2>/dev/null && echo "true"),)
    METAPROG_TARGET = FAILNOPURPLE
    METAPROG_DEST =
        METAPROG_ICONS_DEST =
  else
    METAPROG_TARGET = libmetaprog.so
    METAPROG_DEST = $(DESTDIR)`$(PKG_CONFIG) --variable=plugindir purple`
        METAPROG_ICONS_DEST = $(DESTDIR)`$(PKG_CONFIG) --variable=datadir purple`/pixmaps/pidgin/protocols
  endif
else
  METAPROG_TARGET = libmetaprog3.so
  METAPROG_DEST = $(DESTDIR)`$(PKG_CONFIG) --variable=plugindir purple-3`
      METAPROG_ICONS_DEST = $(DESTDIR)`$(PKG_CONFIG) --variable=datadir purple-3`/pixmaps/pidgin/protocols
endif

C_FILES := libmetaprog.c
PURPLE_COMPAT_FILES := purple2compat/purple-socket.c
PURPLE_C_FILES := libmetaprog.c $(C_FILES)



.PHONY:	all install FAILNOPURPLE clean

all: $(METAPROG_TARGET)

libmetaprog.so: $(PURPLE_C_FILES) $(PURPLE_COMPAT_FILES)
	$(CC) -fPIC $(CFLAGS) -shared -o $@ $^ $(LDFLAGS) `$(PKG_CONFIG) purple glib-2.0 json-glib-1.0 zlib --libs --cflags` -ldl $(INCLUDES) -Ipurple2compat -g -ggdb

libmetaprog3.so: $(PURPLE_C_FILES)
	$(CC) -fPIC $(CFLAGS) -shared -o $@ $^ $(LDFLAGS) `$(PKG_CONFIG) purple-3 glib-2.0 json-glib-1.0 zlib --libs --cflags` -ldl $(INCLUDES) -g -ggdb

install: $(METAPROG_TARGET) install-icons
	mkdir -p $(METAPROG_DEST)
	install -p $(METAPROG_TARGET) $(METAPROG_DEST)

install-icons: metaprog16.png metaprog32.png
	mkdir -p $(METAPROG_ICONS_DEST)/16
	mkdir -p $(METAPROG_ICONS_DEST)/32
	install metaprog16.png $(METAPROG_ICONS_DEST)/16/metaprog.png
	install metaprog32.png $(METAPROG_ICONS_DEST)/32/metaprog.png

FAILNOPURPLE:
	echo "You need libpurple development headers installed to be able to compile this plugin"

clean:
	rm -f $(METAPROG_TARGET)
