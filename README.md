# goosenet

Currently client/server where the server just echo what you typed.

Build via
```bash
sh build.sh
```
which builds `gn-server` and `gn-client`. Now run
```bash
./gn-server 1337
```
to start a server listening on port `1337`. Finally, in another terminal, run
```bash
./gn-client localhost 1337
```
to connect.

:goose:
