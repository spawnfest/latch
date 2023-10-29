defmodule LatchWeb.IngestionController do
  use LatchWeb, :controller

  alias Latch.TraceProcessor
  alias Latch.Trace.Span
  alias Latch.TraceKeeper

  alias Opentelemetry.Proto.Common.V1.KeyValue

  def index(conn, %{}) do
    {:ok, data, _conn_details} = Plug.Conn.read_body(conn)

    decoded =
      Opentelemetry.Proto.Collector.Trace.V1.ExportTraceServiceRequest.decode!(data)

    for resource_span <- decoded.resource_spans do
      service_name_attribute =
        resource_span.resource.attributes
        |> Enum.find(fn %{key: key} -> key == "service.name" end)

      for scope_span <- resource_span.scope_spans do
        scope = scope_span.scope
        spans = scope_span.spans

        service_name =
          case service_name_attribute do
            %KeyValue{value: %{value: {:string_value, value}}} ->
              value

            _ ->
              scope.name
          end

        for span <- spans do
          Span.from_otel_span(span, %{
            scope_name: scope.name,
            service_name: service_name
          })
        end
      end
    end
    |> List.flatten()
    |> Enum.group_by(fn s -> s.trace_id end)
    |> Enum.each(fn {_trace_id, traces} ->
      TraceKeeper.insert_record(traces)
      Phoenix.PubSub.broadcast!(Latch.PubSub, "trace", {:trace, traces})
    end)

    resp =
      %Opentelemetry.Proto.Collector.Trace.V1.ExportTraceServiceResponse{
        partial_success: %Opentelemetry.Proto.Collector.Trace.V1.ExportTracePartialSuccess{
          rejected_spans: 0
        }
      }
      |> Protox.encode!()

    conn
    |> put_resp_content_type("application/x-protobuf")
    |> Plug.Conn.send_resp(200, resp)
  end
end
