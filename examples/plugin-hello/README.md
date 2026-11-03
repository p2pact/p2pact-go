# plugin-hello

A minimal P2PACT plugin in Go. It announces the tool `dev.p2pact.example.hello`:

- method 1 `hello.greet [name]` returns `"Hello, <name>"` (a read method),
- method 2 `hello.bump` increments a counter (a write method),
- event 1 `tick [counter]` every `HELLO_INTERVAL` (default 5s).

The engine hosts the tool for other devices under the same name and forwards calls and events;
read/write is decided by `"read"` in `plugin.json` (methods not listed need write).

Install into a running engine:

```sh
cd agent
go build -o examples/plugin-hello/plugin-hello ./examples/plugin-hello
nomad plugin install examples/plugin-hello
nomad plugin log dev.p2pact.example.hello
```

The plugin gets `P2PACT_SOCKET` and `P2PACT_INVITE` from the engine and pairs with
`p2pact.NewPlugin`; its keys live in `P2PACT_PLUGIN_DATA`.
