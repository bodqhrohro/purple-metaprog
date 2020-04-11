This is a replacement for the extremely awful and mad thing called Metaprog Online (Метапрог Онлайн).

It plugs into libpurple-based clients. Only GNU/Linux is supported for now. For now, the plugin is tested only with Pidgin/libpurple 2.13.0, and is not guaranteed to (but may!) build/work with other UIs or versions. You can find the latest build on the [releases](https://github.com/bodqhrohro/purple-metaprog/releases) page.

To connect to the main (and the only one for now) Metaprog Online server, you need to set up the Tor connection in account settings, and to put in the .onion address and the port of the server on "Advanced" tab.

# Requirements

* glib
* libpurple
* tor

# Build

```
$ make
$ sudo make install
```
