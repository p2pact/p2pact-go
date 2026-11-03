# client-cli

A small P2PACT client application on the [`client`](../../client) package: it pairs with a
computer (a device running a P2PACT engine, e.g. Nomad Code), lists its chats, sends a message
and watches the fleet.

```sh
go run ./examples/client-cli pair p2pact1.…      # invite from `nomad invite`; waits for the person's decision
go run ./examples/client-cli chats              # id, state, agent, folder, title
go run ./examples/client-cli send <chat> "run the tests"   # prints the reply as it streams
go run ./examples/client-cli watch              # fleet events until Ctrl-C
```

Keys and the paired computer live in `$P2PACT_CLIENT_DIR` (default `~/.p2pact-client-cli`).
It asks for chat and fleet in full and the plugins' view; the person at the computer may
narrow that, and `send` fails with `client.ErrForbidden` when the chat is read-only.
