# scuttlebutt-hello

Sample implementation of [Scuttlebutt](https://ssbc.github.io/scuttlebutt-protocol-guide) protocol handshake. 
It can either automatically connect to Scuttlebutt server running on local network via [local network discovery](https://ssbc.github.io/scuttlebutt-protocol-guide/#local-network), or connect to a specific ip and port with provided server long term key.

## Testing

### Run Scuttlebutt server

I'll be using [ssb-server](https://github.com/ssbc/ssb-server) as it's a popular scuttlebutt server with cli interface. Other SSB implementations should of course work too.
Running it requires `npx` which is usually bundled with `npm`.

```sh
$ cd test-server
$ npx ssb-server start --logging.level=info
```

`ssb-server` will print its long term key on startup, client will need that later

```sh
my key ID: LDwmAY+cmuOI+VV7CK2hz78Zh78aL7er2e/lnmJib20=.ed25519
```

`ssb-server` keps it configuration in `~/.ssb`, **if you don't care about any scuttlebutt data there**, it can be removed to generate new server longterm key.

### Run scuttlebutt-hello

##### Manual mode

To connect to a specific node, you need its ip, port, and long term public key (you can pass it with or without `@` prefix and `.ed25519` suffix, program will strip that automatically). Below is example command for locally running `ssb-server`

```sh
$ cargo run -- manual localhost 8008 LDwmAY+cmuOI+VV7CK2hz78Zh78aL7er2e/lnmJib20=
```

##### Discovery mode

Scuttlebutt peers broadcast their presence in local network by constantly sending UDP advertising packets. 
In discovery mode, program will listen for those packets (by default on port 8008) and try to connect to the first peer it finds.

```sc
$ cargo run -- discovery
```

#### Results

##### Success 

Upon successful handshake, program will print out message containing the peer IP and port to stdout, as well as return with a successful exit code.
Note that after handshake, there's also a goodbye message sent, any errors after handshake process are only logged and don't affect the exit code.
```
Connected to peer net:localhost:8008~shs:**** ok
```

On the `ssh-server` side, we can see our client connecting and disconnecting

```
info @LDw SSB- @CIW+wAIiuyqDHksu257htRJzxL+OXpqCYI5nWe792ZI=.ed25519 Connected
info @LDw SSB- @CIW+wAIiuyqDHksu257htRJzxL+OXpqCYI5nWe792ZI=.ed25519 Disconnected
```

##### Failure

When handshake (or other part of the program) fails, program will ultimately panic, printing out the the error and setting unsuccessful exit code. Below is an example output from the program trying to connect with wrong longterm server keys. One can set `RUST_LOG` to higher log level to see more details.

```sh
$ cargo run -- manual localhost 8008 TKDiUzfM9wPklQiy9nfEtwJU/4Yt2D3uJZQz5dipvpg=.ed25519
   Compiling shuttlebutt-hello v0.1.0 (***)
    Finished dev [unoptimized + debuginfo] target(s) in 1.01s
     Running `target/debug/shuttlebutt-hello manual localhost 8008 TKDiUzfM9wPklQiy9nfEtwJU/4Yt2D3uJZQz5dipvpg=.ed25519`
 ERROR shuttlebutt_hello::handshake > connection has been terminated; this can indicate invalid longterm server keys, tampering, or interrupted connection
 ERROR shuttlebutt_hello            > Received error during handshake: Connection interrupted: failed to fill whole buffer
thread 'main' panicked at 'cannot connect to peer: ConnectionInterrupted(Error { kind: UnexpectedEof, message: "failed to fill whole buffer" })', src/main.rs:164:6
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace

```

`ssh-server` will also print out errors, noting the invalid key

```
server error, from net:127.0.0.1:35186~shs:
Error: shs.server: client hello invalid (phase 3). they dailed a wrong number - they didn't have our public key
    at abort (/home/florek/.npm/_npx/e1c67bc2f16a7c86/node_modules/ssb-server/node_modules/secret-handshake/protocol.js:82:45)
    ...
```
