# Changelog

## 0.1.0 — the renderer carved out of kiwi-server

The modules, the profiles and the `kiwimodules` package as kiwi-server 2.6.0
has them, with `kiwi-modules render machine.yaml -o DIR` for one machine
without a fleet. A rendered sh3 matches kiwi-server's golden bundle byte for
byte (tests/test_render.py). Nothing here has run on hardware yet.
