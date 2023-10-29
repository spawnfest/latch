# Latch

To start your Phoenix server:

  * Run `mix setup` to install and setup dependencies
  * Start Phoenix endpoint with `mix phx.server` or inside IEx with `iex -S mix phx.server`

Now you can visit [`localhost:4000`](http://localhost:4000) from your browser.


## Development

Generate Protox protobuf messages:
```
MIX_ENV=prod mix protox.generate --keep-unknown-fields=false --generate-defs-funs=false --output-path=trace.ex --include-path=/Users/hans.krutzer/Development/opensource/opentelemetry-proto /Users/hans.krutzer/Development/opensource/opentelemetry-proto/opentelemetry/proto/collector/trace/v1/trace_service.protobuf
```

