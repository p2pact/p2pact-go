# p2pact-go

The Go implementation of **P2PACT — the P2P Agent Chat Transport Protocol**: chat with your AI agents,
and let them chat with each other, across your own devices — no servers, no accounts, over any
connection.

The protocol itself is specified in [p2pact/p2pact](https://github.com/p2pact/p2pact); this is
the reference implementation. Benchmarks and interop tests live in
[p2pact/p2pact-tests](https://github.com/p2pact/p2pact-tests).

```sh
go get github.com/p2pact/p2pact-go
```

## Use

```go
import "github.com/p2pact/p2pact-go"

laptop, _ := p2pact.NewNode(dir, "Laptop")         // keys and known devices live in dir
_ = laptop.ListenUDP(":48730")
_ = laptop.ListenTCP(":48730")                       // fallback where UDP is blocked
laptop.Handle(1, 2, func(peer string, args []cbor.RawMessage) ([]any, error) {
	return []any{}, nil                                // chat.send: accept a message
})
laptop.Start()

invite := laptop.Invite(10 * time.Minute).String()  // p2pact1.… — show it as a QR code

phone, _ := p2pact.NewNode(otherDir, "Phone")
_ = phone.ListenUDP(":0")
phone.Start()
inv, _ := p2pact.ParseInvite(invite)
peer, _ := phone.Join(ctx, inv)                       // pair once; afterwards they find each other
_, _ = phone.Call(ctx, peer.Addr, 1, 2, 1, "run the tests")
```

- `Call` / `Handle` — calls and results; `Event` / `OnEvent` — events in either direction.
- `CallOn` / `EventOn` — the same on a **stream**: in order within it, independent of other
  streams, so a loss on one chat does not hold up the others. Use one stream per chat.
- `SetAdvertise` — announce given addresses instead of your own (port forwarding, a public
  address).
- `AddDict(p2pact.CommonDict)` — the common compression dictionary (spec §5), used until the
  device has its own. Its own it trains by itself, one per device it talks to, on that
  conversation (kept in `net-history/` next to the keys, shown to nobody else); `NoLearning`
  turns that off, `DictState` tells what compresses messages to a device now.
- `Befriend` — add a device known from the family book without pairing.
- `SetRelay` — your relay for when devices cannot reach each other directly.
- `AttachRoad` — a road your app provides: Bluetooth LE GATT, a serial line, a pipe (spec §3).
  The app implements `Send` and hands what arrives to `Receive`:

  ```go
  // GATT: ordered and acknowledged, writes of ATT MTU − 3 bytes — a stream road
  ble, _ := node.AttachRoad(peer.Addr, gattLink, p2pact.AppRoadConfig{
  	Name: "ble", Stream: true, MTU: mtu - 3, Rate: 40 << 10})
  // in the GATT callbacks (characteristic written, notification received):
  ble.Receive(value)
  // the link dropped:
  ble.Detach()
  ```

  `peer` is the device the link reaches if the app knows it (from its advertisement); `""`
  — learnt from the first handshake on it, and offered to `Join` for pairing. The road is used
  while nothing better is up; the session moves to UDP, TCP or a relay as soon as one answers
  and comes back when they fall silent.

## What is implemented

- Pairing by invite (Noise XXpsk2), sessions with data in the first packet (Noise IK).
- Roads: UDP, TCP, relay, and roads the app provides (datagram or stream: Bluetooth LE). A
  session moves between roads without a new handshake.
- Delivery: streams, ack ranges, congestion control (a window that grows while no queue
  builds, timers from the measured round trip, a delivery-rate limit), retransmission over
  the next live road, long messages in parts.
- Compression: zstd with the common dictionary and dictionaries each device trains for each
  device it talks to (fastCover, as `zstd --train`, with the parameters picked on held-out
  messages).
- Not yet: the family tool, NAT hole punching.

## Relay

```sh
go run ./cmd/p2pact-relay -addr :8443 -data ./relay-data
```

It prints its certificate fingerprint; give devices the address and the fingerprint. The relay
forwards encrypted packets and cannot read them.

## Tests

```sh
go test ./...
go test -v -run Compare .    # sizes and timings against JSON over TLS and HTTPS
```

`cmd/p2pact-interop` is the reference interop peer: other implementations are tested against
it in [p2pact-tests](https://github.com/p2pact/p2pact-tests).

## License

[Apache License 2.0](LICENSE).
