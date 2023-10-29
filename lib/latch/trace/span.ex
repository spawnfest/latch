defmodule Latch.Trace.Span do
  alias Opentelemetry.Proto.Trace.V1.Span, as: OtelSpan

  defstruct [
    :trace_id,
    :span_id,
    :parent_span_id,
    :service_name,
    :scope_name,
    :name,
    :start_time,
    :end_time,
    :attributes,
    :kind,
    :status
  ]

  def from_otel_span(
        %OtelSpan{
          trace_id: trace_id,
          span_id: span_id,
          parent_span_id: parent_span_id,
          name: name,
          kind: kind,
          start_time_unix_nano: start_time_unix_nano,
          end_time_unix_nano: end_time_unix_nano,
          status: status,
          attributes: attributes
        },
        %{
          service_name: service_name,
          scope_name: scope_name
        }
      ) do
    %__MODULE__{
      trace_id: Base.encode16(trace_id),
      span_id: Base.encode16(span_id),
      parent_span_id: Base.encode16(parent_span_id),
      name: name,
      service_name: service_name,
      scope_name: scope_name,
      start_time: DateTime.from_unix!(start_time_unix_nano, :nanosecond),
      end_time: DateTime.from_unix!(end_time_unix_nano, :nanosecond),
      attributes: attributes,
      kind: kind,
      status: status
    }
  end
end
