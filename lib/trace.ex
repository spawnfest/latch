# credo:disable-for-this-file
[
  defmodule Opentelemetry.Proto.Trace.V1.Span.SpanKind do
    @moduledoc false
    (
      defstruct []

      (
        @spec default() :: :SPAN_KIND_UNSPECIFIED
        def default() do
          :SPAN_KIND_UNSPECIFIED
        end
      )

      @spec encode(atom() | String.t()) :: integer() | atom()
      [
        (
          def encode(:SPAN_KIND_UNSPECIFIED) do
            0
          end

          def encode("SPAN_KIND_UNSPECIFIED") do
            0
          end
        ),
        (
          def encode(:SPAN_KIND_INTERNAL) do
            1
          end

          def encode("SPAN_KIND_INTERNAL") do
            1
          end
        ),
        (
          def encode(:SPAN_KIND_SERVER) do
            2
          end

          def encode("SPAN_KIND_SERVER") do
            2
          end
        ),
        (
          def encode(:SPAN_KIND_CLIENT) do
            3
          end

          def encode("SPAN_KIND_CLIENT") do
            3
          end
        ),
        (
          def encode(:SPAN_KIND_PRODUCER) do
            4
          end

          def encode("SPAN_KIND_PRODUCER") do
            4
          end
        ),
        (
          def encode(:SPAN_KIND_CONSUMER) do
            5
          end

          def encode("SPAN_KIND_CONSUMER") do
            5
          end
        )
      ]

      def encode(x) do
        x
      end

      @spec decode(integer()) :: atom() | integer()
      [
        def decode(0) do
          :SPAN_KIND_UNSPECIFIED
        end,
        def decode(1) do
          :SPAN_KIND_INTERNAL
        end,
        def decode(2) do
          :SPAN_KIND_SERVER
        end,
        def decode(3) do
          :SPAN_KIND_CLIENT
        end,
        def decode(4) do
          :SPAN_KIND_PRODUCER
        end,
        def decode(5) do
          :SPAN_KIND_CONSUMER
        end
      ]

      def decode(x) do
        x
      end

      @spec constants() :: [{integer(), atom()}]
      def constants() do
        [
          {0, :SPAN_KIND_UNSPECIFIED},
          {1, :SPAN_KIND_INTERNAL},
          {2, :SPAN_KIND_SERVER},
          {3, :SPAN_KIND_CLIENT},
          {4, :SPAN_KIND_PRODUCER},
          {5, :SPAN_KIND_CONSUMER}
        ]
      end

      @spec has_constant?(any()) :: boolean()
      (
        [
          def has_constant?(:SPAN_KIND_UNSPECIFIED) do
            true
          end,
          def has_constant?(:SPAN_KIND_INTERNAL) do
            true
          end,
          def has_constant?(:SPAN_KIND_SERVER) do
            true
          end,
          def has_constant?(:SPAN_KIND_CLIENT) do
            true
          end,
          def has_constant?(:SPAN_KIND_PRODUCER) do
            true
          end,
          def has_constant?(:SPAN_KIND_CONSUMER) do
            true
          end
        ]

        def has_constant?(_) do
          false
        end
      )
    )
  end,
  defmodule Opentelemetry.Proto.Trace.V1.SpanFlags do
    @moduledoc false
    (
      defstruct []

      (
        @spec default() :: :SPAN_FLAGS_DO_NOT_USE
        def default() do
          :SPAN_FLAGS_DO_NOT_USE
        end
      )

      @spec encode(atom() | String.t()) :: integer() | atom()
      [
        (
          def encode(:SPAN_FLAGS_DO_NOT_USE) do
            0
          end

          def encode("SPAN_FLAGS_DO_NOT_USE") do
            0
          end
        ),
        (
          def encode(:SPAN_FLAGS_TRACE_FLAGS_MASK) do
            255
          end

          def encode("SPAN_FLAGS_TRACE_FLAGS_MASK") do
            255
          end
        )
      ]

      def encode(x) do
        x
      end

      @spec decode(integer()) :: atom() | integer()
      [
        def decode(0) do
          :SPAN_FLAGS_DO_NOT_USE
        end,
        def decode(255) do
          :SPAN_FLAGS_TRACE_FLAGS_MASK
        end
      ]

      def decode(x) do
        x
      end

      @spec constants() :: [{integer(), atom()}]
      def constants() do
        [{0, :SPAN_FLAGS_DO_NOT_USE}, {255, :SPAN_FLAGS_TRACE_FLAGS_MASK}]
      end

      @spec has_constant?(any()) :: boolean()
      (
        [
          def has_constant?(:SPAN_FLAGS_DO_NOT_USE) do
            true
          end,
          def has_constant?(:SPAN_FLAGS_TRACE_FLAGS_MASK) do
            true
          end
        ]

        def has_constant?(_) do
          false
        end
      )
    )
  end,
  defmodule Opentelemetry.Proto.Trace.V1.Status.StatusCode do
    @moduledoc false
    (
      defstruct []

      (
        @spec default() :: :STATUS_CODE_UNSET
        def default() do
          :STATUS_CODE_UNSET
        end
      )

      @spec encode(atom() | String.t()) :: integer() | atom()
      [
        (
          def encode(:STATUS_CODE_UNSET) do
            0
          end

          def encode("STATUS_CODE_UNSET") do
            0
          end
        ),
        (
          def encode(:STATUS_CODE_OK) do
            1
          end

          def encode("STATUS_CODE_OK") do
            1
          end
        ),
        (
          def encode(:STATUS_CODE_ERROR) do
            2
          end

          def encode("STATUS_CODE_ERROR") do
            2
          end
        )
      ]

      def encode(x) do
        x
      end

      @spec decode(integer()) :: atom() | integer()
      [
        def decode(0) do
          :STATUS_CODE_UNSET
        end,
        def decode(1) do
          :STATUS_CODE_OK
        end,
        def decode(2) do
          :STATUS_CODE_ERROR
        end
      ]

      def decode(x) do
        x
      end

      @spec constants() :: [{integer(), atom()}]
      def constants() do
        [{0, :STATUS_CODE_UNSET}, {1, :STATUS_CODE_OK}, {2, :STATUS_CODE_ERROR}]
      end

      @spec has_constant?(any()) :: boolean()
      (
        [
          def has_constant?(:STATUS_CODE_UNSET) do
            true
          end,
          def has_constant?(:STATUS_CODE_OK) do
            true
          end,
          def has_constant?(:STATUS_CODE_ERROR) do
            true
          end
        ]

        def has_constant?(_) do
          false
        end
      )
    )
  end,
  defmodule Opentelemetry.Proto.Collector.Trace.V1.ExportTracePartialSuccess do
    @moduledoc false
    defstruct rejected_spans: 0, error_message: ""

    (
      (
        @spec encode(struct) :: {:ok, iodata} | {:error, any}
        def encode(msg) do
          try do
            {:ok, encode!(msg)}
          rescue
            e in [Protox.EncodingError, Protox.RequiredFieldsError] -> {:error, e}
          end
        end

        @spec encode!(struct) :: iodata | no_return
        def encode!(msg) do
          [] |> encode_rejected_spans(msg) |> encode_error_message(msg)
        end
      )

      []

      [
        defp encode_rejected_spans(acc, msg) do
          try do
            if msg.rejected_spans == 0 do
              acc
            else
              [acc, "\b", Protox.Encode.encode_int64(msg.rejected_spans)]
            end
          rescue
            ArgumentError ->
              reraise Protox.EncodingError.new(:rejected_spans, "invalid field value"),
                      __STACKTRACE__
          end
        end,
        defp encode_error_message(acc, msg) do
          try do
            if msg.error_message == "" do
              acc
            else
              [acc, "\x12", Protox.Encode.encode_string(msg.error_message)]
            end
          rescue
            ArgumentError ->
              reraise Protox.EncodingError.new(:error_message, "invalid field value"),
                      __STACKTRACE__
          end
        end
      ]

      []
    )

    (
      (
        @spec decode(binary) :: {:ok, struct} | {:error, any}
        def decode(bytes) do
          try do
            {:ok, decode!(bytes)}
          rescue
            e in [Protox.DecodingError, Protox.IllegalTagError, Protox.RequiredFieldsError] ->
              {:error, e}
          end
        end

        (
          @spec decode!(binary) :: struct | no_return
          def decode!(bytes) do
            parse_key_value(
              bytes,
              struct(Opentelemetry.Proto.Collector.Trace.V1.ExportTracePartialSuccess)
            )
          end
        )
      )

      (
        @spec parse_key_value(binary, struct) :: struct
        defp parse_key_value(<<>>, msg) do
          msg
        end

        defp parse_key_value(bytes, msg) do
          {field, rest} =
            case Protox.Decode.parse_key(bytes) do
              {0, _, _} ->
                raise %Protox.IllegalTagError{}

              {1, _, bytes} ->
                {value, rest} = Protox.Decode.parse_int64(bytes)
                {[rejected_spans: value], rest}

              {2, _, bytes} ->
                {len, bytes} = Protox.Varint.decode(bytes)
                {delimited, rest} = Protox.Decode.parse_delimited(bytes, len)
                {[error_message: delimited], rest}

              {tag, wire_type, rest} ->
                {_, rest} = Protox.Decode.parse_unknown(tag, wire_type, rest)
                {[], rest}
            end

          msg_updated = struct(msg, field)
          parse_key_value(rest, msg_updated)
        end
      )

      []
    )

    (
      @spec json_decode(iodata(), keyword()) :: {:ok, struct()} | {:error, any()}
      def json_decode(input, opts \\ []) do
        try do
          {:ok, json_decode!(input, opts)}
        rescue
          e in Protox.JsonDecodingError -> {:error, e}
        end
      end

      @spec json_decode!(iodata(), keyword()) :: struct() | no_return()
      def json_decode!(input, opts \\ []) do
        {json_library_wrapper, json_library} = Protox.JsonLibrary.get_library(opts, :decode)

        Protox.JsonDecode.decode!(
          input,
          Opentelemetry.Proto.Collector.Trace.V1.ExportTracePartialSuccess,
          &json_library_wrapper.decode!(json_library, &1)
        )
      end

      @spec json_encode(struct(), keyword()) :: {:ok, iodata()} | {:error, any()}
      def json_encode(msg, opts \\ []) do
        try do
          {:ok, json_encode!(msg, opts)}
        rescue
          e in Protox.JsonEncodingError -> {:error, e}
        end
      end

      @spec json_encode!(struct(), keyword()) :: iodata() | no_return()
      def json_encode!(msg, opts \\ []) do
        {json_library_wrapper, json_library} = Protox.JsonLibrary.get_library(opts, :encode)
        Protox.JsonEncode.encode!(msg, &json_library_wrapper.encode!(json_library, &1))
      end
    )

    []

    (
      @spec fields_defs() :: list(Protox.Field.t())
      def fields_defs() do
        [
          %{
            __struct__: Protox.Field,
            json_name: "rejectedSpans",
            kind: {:scalar, 0},
            label: :optional,
            name: :rejected_spans,
            tag: 1,
            type: :int64
          },
          %{
            __struct__: Protox.Field,
            json_name: "errorMessage",
            kind: {:scalar, ""},
            label: :optional,
            name: :error_message,
            tag: 2,
            type: :string
          }
        ]
      end

      [
        @spec(field_def(atom) :: {:ok, Protox.Field.t()} | {:error, :no_such_field}),
        (
          def field_def(:rejected_spans) do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "rejectedSpans",
               kind: {:scalar, 0},
               label: :optional,
               name: :rejected_spans,
               tag: 1,
               type: :int64
             }}
          end

          def field_def("rejectedSpans") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "rejectedSpans",
               kind: {:scalar, 0},
               label: :optional,
               name: :rejected_spans,
               tag: 1,
               type: :int64
             }}
          end

          def field_def("rejected_spans") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "rejectedSpans",
               kind: {:scalar, 0},
               label: :optional,
               name: :rejected_spans,
               tag: 1,
               type: :int64
             }}
          end
        ),
        (
          def field_def(:error_message) do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "errorMessage",
               kind: {:scalar, ""},
               label: :optional,
               name: :error_message,
               tag: 2,
               type: :string
             }}
          end

          def field_def("errorMessage") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "errorMessage",
               kind: {:scalar, ""},
               label: :optional,
               name: :error_message,
               tag: 2,
               type: :string
             }}
          end

          def field_def("error_message") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "errorMessage",
               kind: {:scalar, ""},
               label: :optional,
               name: :error_message,
               tag: 2,
               type: :string
             }}
          end
        ),
        def field_def(_) do
          {:error, :no_such_field}
        end
      ]
    )

    []

    (
      @spec required_fields() :: []
      def required_fields() do
        []
      end
    )

    (
      @spec syntax() :: atom()
      def syntax() do
        :proto3
      end
    )

    [
      @spec(default(atom) :: {:ok, boolean | integer | String.t() | float} | {:error, atom}),
      def default(:rejected_spans) do
        {:ok, 0}
      end,
      def default(:error_message) do
        {:ok, ""}
      end,
      def default(_) do
        {:error, :no_such_field}
      end
    ]

    (
      @spec file_options() :: struct()
      def file_options() do
        file_options = %{
          __struct__: Protox.Google.Protobuf.FileOptions,
          __uf__: [],
          cc_enable_arenas: nil,
          cc_generic_services: nil,
          csharp_namespace: "OpenTelemetry.Proto.Collector.Trace.V1",
          deprecated: nil,
          go_package: "go.opentelemetry.io/proto/otlp/collector/trace/v1",
          java_generate_equals_and_hash: nil,
          java_generic_services: nil,
          java_multiple_files: true,
          java_outer_classname: "TraceServiceProto",
          java_package: "io.opentelemetry.proto.collector.trace.v1",
          java_string_check_utf8: nil,
          objc_class_prefix: nil,
          optimize_for: nil,
          php_class_prefix: nil,
          php_generic_services: nil,
          php_metadata_namespace: nil,
          php_namespace: nil,
          py_generic_services: nil,
          ruby_package: nil,
          swift_prefix: nil,
          uninterpreted_option: []
        }

        case function_exported?(Google.Protobuf.FileOptions, :decode!, 1) do
          true ->
            bytes =
              file_options
              |> Protox.Google.Protobuf.FileOptions.encode!()
              |> :binary.list_to_bin()

            apply(Google.Protobuf.FileOptions, :decode!, [bytes])

          false ->
            file_options
        end
      end
    )
  end,
  defmodule Opentelemetry.Proto.Collector.Trace.V1.ExportTraceServiceRequest do
    @moduledoc false
    defstruct resource_spans: []

    (
      (
        @spec encode(struct) :: {:ok, iodata} | {:error, any}
        def encode(msg) do
          try do
            {:ok, encode!(msg)}
          rescue
            e in [Protox.EncodingError, Protox.RequiredFieldsError] -> {:error, e}
          end
        end

        @spec encode!(struct) :: iodata | no_return
        def encode!(msg) do
          [] |> encode_resource_spans(msg)
        end
      )

      []

      [
        defp encode_resource_spans(acc, msg) do
          try do
            case msg.resource_spans do
              [] ->
                acc

              values ->
                [
                  acc,
                  Enum.reduce(values, [], fn value, acc ->
                    [acc, "\n", Protox.Encode.encode_message(value)]
                  end)
                ]
            end
          rescue
            ArgumentError ->
              reraise Protox.EncodingError.new(:resource_spans, "invalid field value"),
                      __STACKTRACE__
          end
        end
      ]

      []
    )

    (
      (
        @spec decode(binary) :: {:ok, struct} | {:error, any}
        def decode(bytes) do
          try do
            {:ok, decode!(bytes)}
          rescue
            e in [Protox.DecodingError, Protox.IllegalTagError, Protox.RequiredFieldsError] ->
              {:error, e}
          end
        end

        (
          @spec decode!(binary) :: struct | no_return
          def decode!(bytes) do
            parse_key_value(
              bytes,
              struct(Opentelemetry.Proto.Collector.Trace.V1.ExportTraceServiceRequest)
            )
          end
        )
      )

      (
        @spec parse_key_value(binary, struct) :: struct
        defp parse_key_value(<<>>, msg) do
          msg
        end

        defp parse_key_value(bytes, msg) do
          {field, rest} =
            case Protox.Decode.parse_key(bytes) do
              {0, _, _} ->
                raise %Protox.IllegalTagError{}

              {1, _, bytes} ->
                {len, bytes} = Protox.Varint.decode(bytes)
                {delimited, rest} = Protox.Decode.parse_delimited(bytes, len)

                {[
                   resource_spans:
                     msg.resource_spans ++
                       [Opentelemetry.Proto.Trace.V1.ResourceSpans.decode!(delimited)]
                 ], rest}

              {tag, wire_type, rest} ->
                {_, rest} = Protox.Decode.parse_unknown(tag, wire_type, rest)
                {[], rest}
            end

          msg_updated = struct(msg, field)
          parse_key_value(rest, msg_updated)
        end
      )

      []
    )

    (
      @spec json_decode(iodata(), keyword()) :: {:ok, struct()} | {:error, any()}
      def json_decode(input, opts \\ []) do
        try do
          {:ok, json_decode!(input, opts)}
        rescue
          e in Protox.JsonDecodingError -> {:error, e}
        end
      end

      @spec json_decode!(iodata(), keyword()) :: struct() | no_return()
      def json_decode!(input, opts \\ []) do
        {json_library_wrapper, json_library} = Protox.JsonLibrary.get_library(opts, :decode)

        Protox.JsonDecode.decode!(
          input,
          Opentelemetry.Proto.Collector.Trace.V1.ExportTraceServiceRequest,
          &json_library_wrapper.decode!(json_library, &1)
        )
      end

      @spec json_encode(struct(), keyword()) :: {:ok, iodata()} | {:error, any()}
      def json_encode(msg, opts \\ []) do
        try do
          {:ok, json_encode!(msg, opts)}
        rescue
          e in Protox.JsonEncodingError -> {:error, e}
        end
      end

      @spec json_encode!(struct(), keyword()) :: iodata() | no_return()
      def json_encode!(msg, opts \\ []) do
        {json_library_wrapper, json_library} = Protox.JsonLibrary.get_library(opts, :encode)
        Protox.JsonEncode.encode!(msg, &json_library_wrapper.encode!(json_library, &1))
      end
    )

    []

    (
      @spec fields_defs() :: list(Protox.Field.t())
      def fields_defs() do
        [
          %{
            __struct__: Protox.Field,
            json_name: "resourceSpans",
            kind: :unpacked,
            label: :repeated,
            name: :resource_spans,
            tag: 1,
            type: {:message, Opentelemetry.Proto.Trace.V1.ResourceSpans}
          }
        ]
      end

      [
        @spec(field_def(atom) :: {:ok, Protox.Field.t()} | {:error, :no_such_field}),
        (
          def field_def(:resource_spans) do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "resourceSpans",
               kind: :unpacked,
               label: :repeated,
               name: :resource_spans,
               tag: 1,
               type: {:message, Opentelemetry.Proto.Trace.V1.ResourceSpans}
             }}
          end

          def field_def("resourceSpans") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "resourceSpans",
               kind: :unpacked,
               label: :repeated,
               name: :resource_spans,
               tag: 1,
               type: {:message, Opentelemetry.Proto.Trace.V1.ResourceSpans}
             }}
          end

          def field_def("resource_spans") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "resourceSpans",
               kind: :unpacked,
               label: :repeated,
               name: :resource_spans,
               tag: 1,
               type: {:message, Opentelemetry.Proto.Trace.V1.ResourceSpans}
             }}
          end
        ),
        def field_def(_) do
          {:error, :no_such_field}
        end
      ]
    )

    []

    (
      @spec required_fields() :: []
      def required_fields() do
        []
      end
    )

    (
      @spec syntax() :: atom()
      def syntax() do
        :proto3
      end
    )

    [
      @spec(default(atom) :: {:ok, boolean | integer | String.t() | float} | {:error, atom}),
      def default(:resource_spans) do
        {:error, :no_default_value}
      end,
      def default(_) do
        {:error, :no_such_field}
      end
    ]

    (
      @spec file_options() :: struct()
      def file_options() do
        file_options = %{
          __struct__: Protox.Google.Protobuf.FileOptions,
          __uf__: [],
          cc_enable_arenas: nil,
          cc_generic_services: nil,
          csharp_namespace: "OpenTelemetry.Proto.Collector.Trace.V1",
          deprecated: nil,
          go_package: "go.opentelemetry.io/proto/otlp/collector/trace/v1",
          java_generate_equals_and_hash: nil,
          java_generic_services: nil,
          java_multiple_files: true,
          java_outer_classname: "TraceServiceProto",
          java_package: "io.opentelemetry.proto.collector.trace.v1",
          java_string_check_utf8: nil,
          objc_class_prefix: nil,
          optimize_for: nil,
          php_class_prefix: nil,
          php_generic_services: nil,
          php_metadata_namespace: nil,
          php_namespace: nil,
          py_generic_services: nil,
          ruby_package: nil,
          swift_prefix: nil,
          uninterpreted_option: []
        }

        case function_exported?(Google.Protobuf.FileOptions, :decode!, 1) do
          true ->
            bytes =
              file_options
              |> Protox.Google.Protobuf.FileOptions.encode!()
              |> :binary.list_to_bin()

            apply(Google.Protobuf.FileOptions, :decode!, [bytes])

          false ->
            file_options
        end
      end
    )
  end,
  defmodule Opentelemetry.Proto.Collector.Trace.V1.ExportTraceServiceResponse do
    @moduledoc false
    defstruct partial_success: nil

    (
      (
        @spec encode(struct) :: {:ok, iodata} | {:error, any}
        def encode(msg) do
          try do
            {:ok, encode!(msg)}
          rescue
            e in [Protox.EncodingError, Protox.RequiredFieldsError] -> {:error, e}
          end
        end

        @spec encode!(struct) :: iodata | no_return
        def encode!(msg) do
          [] |> encode_partial_success(msg)
        end
      )

      []

      [
        defp encode_partial_success(acc, msg) do
          try do
            if msg.partial_success == nil do
              acc
            else
              [acc, "\n", Protox.Encode.encode_message(msg.partial_success)]
            end
          rescue
            ArgumentError ->
              reraise Protox.EncodingError.new(:partial_success, "invalid field value"),
                      __STACKTRACE__
          end
        end
      ]

      []
    )

    (
      (
        @spec decode(binary) :: {:ok, struct} | {:error, any}
        def decode(bytes) do
          try do
            {:ok, decode!(bytes)}
          rescue
            e in [Protox.DecodingError, Protox.IllegalTagError, Protox.RequiredFieldsError] ->
              {:error, e}
          end
        end

        (
          @spec decode!(binary) :: struct | no_return
          def decode!(bytes) do
            parse_key_value(
              bytes,
              struct(Opentelemetry.Proto.Collector.Trace.V1.ExportTraceServiceResponse)
            )
          end
        )
      )

      (
        @spec parse_key_value(binary, struct) :: struct
        defp parse_key_value(<<>>, msg) do
          msg
        end

        defp parse_key_value(bytes, msg) do
          {field, rest} =
            case Protox.Decode.parse_key(bytes) do
              {0, _, _} ->
                raise %Protox.IllegalTagError{}

              {1, _, bytes} ->
                {len, bytes} = Protox.Varint.decode(bytes)
                {delimited, rest} = Protox.Decode.parse_delimited(bytes, len)

                {[
                   partial_success:
                     Protox.MergeMessage.merge(
                       msg.partial_success,
                       Opentelemetry.Proto.Collector.Trace.V1.ExportTracePartialSuccess.decode!(
                         delimited
                       )
                     )
                 ], rest}

              {tag, wire_type, rest} ->
                {_, rest} = Protox.Decode.parse_unknown(tag, wire_type, rest)
                {[], rest}
            end

          msg_updated = struct(msg, field)
          parse_key_value(rest, msg_updated)
        end
      )

      []
    )

    (
      @spec json_decode(iodata(), keyword()) :: {:ok, struct()} | {:error, any()}
      def json_decode(input, opts \\ []) do
        try do
          {:ok, json_decode!(input, opts)}
        rescue
          e in Protox.JsonDecodingError -> {:error, e}
        end
      end

      @spec json_decode!(iodata(), keyword()) :: struct() | no_return()
      def json_decode!(input, opts \\ []) do
        {json_library_wrapper, json_library} = Protox.JsonLibrary.get_library(opts, :decode)

        Protox.JsonDecode.decode!(
          input,
          Opentelemetry.Proto.Collector.Trace.V1.ExportTraceServiceResponse,
          &json_library_wrapper.decode!(json_library, &1)
        )
      end

      @spec json_encode(struct(), keyword()) :: {:ok, iodata()} | {:error, any()}
      def json_encode(msg, opts \\ []) do
        try do
          {:ok, json_encode!(msg, opts)}
        rescue
          e in Protox.JsonEncodingError -> {:error, e}
        end
      end

      @spec json_encode!(struct(), keyword()) :: iodata() | no_return()
      def json_encode!(msg, opts \\ []) do
        {json_library_wrapper, json_library} = Protox.JsonLibrary.get_library(opts, :encode)
        Protox.JsonEncode.encode!(msg, &json_library_wrapper.encode!(json_library, &1))
      end
    )

    []

    (
      @spec fields_defs() :: list(Protox.Field.t())
      def fields_defs() do
        [
          %{
            __struct__: Protox.Field,
            json_name: "partialSuccess",
            kind: {:scalar, nil},
            label: :optional,
            name: :partial_success,
            tag: 1,
            type: {:message, Opentelemetry.Proto.Collector.Trace.V1.ExportTracePartialSuccess}
          }
        ]
      end

      [
        @spec(field_def(atom) :: {:ok, Protox.Field.t()} | {:error, :no_such_field}),
        (
          def field_def(:partial_success) do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "partialSuccess",
               kind: {:scalar, nil},
               label: :optional,
               name: :partial_success,
               tag: 1,
               type: {:message, Opentelemetry.Proto.Collector.Trace.V1.ExportTracePartialSuccess}
             }}
          end

          def field_def("partialSuccess") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "partialSuccess",
               kind: {:scalar, nil},
               label: :optional,
               name: :partial_success,
               tag: 1,
               type: {:message, Opentelemetry.Proto.Collector.Trace.V1.ExportTracePartialSuccess}
             }}
          end

          def field_def("partial_success") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "partialSuccess",
               kind: {:scalar, nil},
               label: :optional,
               name: :partial_success,
               tag: 1,
               type: {:message, Opentelemetry.Proto.Collector.Trace.V1.ExportTracePartialSuccess}
             }}
          end
        ),
        def field_def(_) do
          {:error, :no_such_field}
        end
      ]
    )

    []

    (
      @spec required_fields() :: []
      def required_fields() do
        []
      end
    )

    (
      @spec syntax() :: atom()
      def syntax() do
        :proto3
      end
    )

    [
      @spec(default(atom) :: {:ok, boolean | integer | String.t() | float} | {:error, atom}),
      def default(:partial_success) do
        {:ok, nil}
      end,
      def default(_) do
        {:error, :no_such_field}
      end
    ]

    (
      @spec file_options() :: struct()
      def file_options() do
        file_options = %{
          __struct__: Protox.Google.Protobuf.FileOptions,
          __uf__: [],
          cc_enable_arenas: nil,
          cc_generic_services: nil,
          csharp_namespace: "OpenTelemetry.Proto.Collector.Trace.V1",
          deprecated: nil,
          go_package: "go.opentelemetry.io/proto/otlp/collector/trace/v1",
          java_generate_equals_and_hash: nil,
          java_generic_services: nil,
          java_multiple_files: true,
          java_outer_classname: "TraceServiceProto",
          java_package: "io.opentelemetry.proto.collector.trace.v1",
          java_string_check_utf8: nil,
          objc_class_prefix: nil,
          optimize_for: nil,
          php_class_prefix: nil,
          php_generic_services: nil,
          php_metadata_namespace: nil,
          php_namespace: nil,
          py_generic_services: nil,
          ruby_package: nil,
          swift_prefix: nil,
          uninterpreted_option: []
        }

        case function_exported?(Google.Protobuf.FileOptions, :decode!, 1) do
          true ->
            bytes =
              file_options
              |> Protox.Google.Protobuf.FileOptions.encode!()
              |> :binary.list_to_bin()

            apply(Google.Protobuf.FileOptions, :decode!, [bytes])

          false ->
            file_options
        end
      end
    )
  end,
  defmodule Opentelemetry.Proto.Common.V1.AnyValue do
    @moduledoc false
    defstruct value: nil

    (
      (
        @spec encode(struct) :: {:ok, iodata} | {:error, any}
        def encode(msg) do
          try do
            {:ok, encode!(msg)}
          rescue
            e in [Protox.EncodingError, Protox.RequiredFieldsError] -> {:error, e}
          end
        end

        @spec encode!(struct) :: iodata | no_return
        def encode!(msg) do
          [] |> encode_value(msg)
        end
      )

      [
        defp encode_value(acc, msg) do
          case msg.value do
            nil -> acc
            {:string_value, _field_value} -> encode_string_value(acc, msg)
            {:bool_value, _field_value} -> encode_bool_value(acc, msg)
            {:int_value, _field_value} -> encode_int_value(acc, msg)
            {:double_value, _field_value} -> encode_double_value(acc, msg)
            {:array_value, _field_value} -> encode_array_value(acc, msg)
            {:kvlist_value, _field_value} -> encode_kvlist_value(acc, msg)
            {:bytes_value, _field_value} -> encode_bytes_value(acc, msg)
          end
        end
      ]

      [
        defp encode_string_value(acc, msg) do
          try do
            {_, child_field_value} = msg.value
            [acc, "\n", Protox.Encode.encode_string(child_field_value)]
          rescue
            ArgumentError ->
              reraise Protox.EncodingError.new(:string_value, "invalid field value"),
                      __STACKTRACE__
          end
        end,
        defp encode_bool_value(acc, msg) do
          try do
            {_, child_field_value} = msg.value
            [acc, "\x10", Protox.Encode.encode_bool(child_field_value)]
          rescue
            ArgumentError ->
              reraise Protox.EncodingError.new(:bool_value, "invalid field value"), __STACKTRACE__
          end
        end,
        defp encode_int_value(acc, msg) do
          try do
            {_, child_field_value} = msg.value
            [acc, "\x18", Protox.Encode.encode_int64(child_field_value)]
          rescue
            ArgumentError ->
              reraise Protox.EncodingError.new(:int_value, "invalid field value"), __STACKTRACE__
          end
        end,
        defp encode_double_value(acc, msg) do
          try do
            {_, child_field_value} = msg.value
            [acc, "!", Protox.Encode.encode_double(child_field_value)]
          rescue
            ArgumentError ->
              reraise Protox.EncodingError.new(:double_value, "invalid field value"),
                      __STACKTRACE__
          end
        end,
        defp encode_array_value(acc, msg) do
          try do
            {_, child_field_value} = msg.value
            [acc, "*", Protox.Encode.encode_message(child_field_value)]
          rescue
            ArgumentError ->
              reraise Protox.EncodingError.new(:array_value, "invalid field value"),
                      __STACKTRACE__
          end
        end,
        defp encode_kvlist_value(acc, msg) do
          try do
            {_, child_field_value} = msg.value
            [acc, "2", Protox.Encode.encode_message(child_field_value)]
          rescue
            ArgumentError ->
              reraise Protox.EncodingError.new(:kvlist_value, "invalid field value"),
                      __STACKTRACE__
          end
        end,
        defp encode_bytes_value(acc, msg) do
          try do
            {_, child_field_value} = msg.value
            [acc, ":", Protox.Encode.encode_bytes(child_field_value)]
          rescue
            ArgumentError ->
              reraise Protox.EncodingError.new(:bytes_value, "invalid field value"),
                      __STACKTRACE__
          end
        end
      ]

      []
    )

    (
      (
        @spec decode(binary) :: {:ok, struct} | {:error, any}
        def decode(bytes) do
          try do
            {:ok, decode!(bytes)}
          rescue
            e in [Protox.DecodingError, Protox.IllegalTagError, Protox.RequiredFieldsError] ->
              {:error, e}
          end
        end

        (
          @spec decode!(binary) :: struct | no_return
          def decode!(bytes) do
            parse_key_value(bytes, struct(Opentelemetry.Proto.Common.V1.AnyValue))
          end
        )
      )

      (
        @spec parse_key_value(binary, struct) :: struct
        defp parse_key_value(<<>>, msg) do
          msg
        end

        defp parse_key_value(bytes, msg) do
          {field, rest} =
            case Protox.Decode.parse_key(bytes) do
              {0, _, _} ->
                raise %Protox.IllegalTagError{}

              {1, _, bytes} ->
                {len, bytes} = Protox.Varint.decode(bytes)
                {delimited, rest} = Protox.Decode.parse_delimited(bytes, len)
                {[value: {:string_value, delimited}], rest}

              {2, _, bytes} ->
                {value, rest} = Protox.Decode.parse_bool(bytes)
                {[value: {:bool_value, value}], rest}

              {3, _, bytes} ->
                {value, rest} = Protox.Decode.parse_int64(bytes)
                {[value: {:int_value, value}], rest}

              {4, _, bytes} ->
                {value, rest} = Protox.Decode.parse_double(bytes)
                {[value: {:double_value, value}], rest}

              {5, _, bytes} ->
                {len, bytes} = Protox.Varint.decode(bytes)
                {delimited, rest} = Protox.Decode.parse_delimited(bytes, len)

                {[
                   case msg.value do
                     {:array_value, previous_value} ->
                       {:value,
                        {:array_value,
                         Protox.MergeMessage.merge(
                           previous_value,
                           Opentelemetry.Proto.Common.V1.ArrayValue.decode!(delimited)
                         )}}

                     _ ->
                       {:value,
                        {:array_value,
                         Opentelemetry.Proto.Common.V1.ArrayValue.decode!(delimited)}}
                   end
                 ], rest}

              {6, _, bytes} ->
                {len, bytes} = Protox.Varint.decode(bytes)
                {delimited, rest} = Protox.Decode.parse_delimited(bytes, len)

                {[
                   case msg.value do
                     {:kvlist_value, previous_value} ->
                       {:value,
                        {:kvlist_value,
                         Protox.MergeMessage.merge(
                           previous_value,
                           Opentelemetry.Proto.Common.V1.KeyValueList.decode!(delimited)
                         )}}

                     _ ->
                       {:value,
                        {:kvlist_value,
                         Opentelemetry.Proto.Common.V1.KeyValueList.decode!(delimited)}}
                   end
                 ], rest}

              {7, _, bytes} ->
                {len, bytes} = Protox.Varint.decode(bytes)
                {delimited, rest} = Protox.Decode.parse_delimited(bytes, len)
                {[value: {:bytes_value, delimited}], rest}

              {tag, wire_type, rest} ->
                {_, rest} = Protox.Decode.parse_unknown(tag, wire_type, rest)
                {[], rest}
            end

          msg_updated = struct(msg, field)
          parse_key_value(rest, msg_updated)
        end
      )

      []
    )

    (
      @spec json_decode(iodata(), keyword()) :: {:ok, struct()} | {:error, any()}
      def json_decode(input, opts \\ []) do
        try do
          {:ok, json_decode!(input, opts)}
        rescue
          e in Protox.JsonDecodingError -> {:error, e}
        end
      end

      @spec json_decode!(iodata(), keyword()) :: struct() | no_return()
      def json_decode!(input, opts \\ []) do
        {json_library_wrapper, json_library} = Protox.JsonLibrary.get_library(opts, :decode)

        Protox.JsonDecode.decode!(
          input,
          Opentelemetry.Proto.Common.V1.AnyValue,
          &json_library_wrapper.decode!(json_library, &1)
        )
      end

      @spec json_encode(struct(), keyword()) :: {:ok, iodata()} | {:error, any()}
      def json_encode(msg, opts \\ []) do
        try do
          {:ok, json_encode!(msg, opts)}
        rescue
          e in Protox.JsonEncodingError -> {:error, e}
        end
      end

      @spec json_encode!(struct(), keyword()) :: iodata() | no_return()
      def json_encode!(msg, opts \\ []) do
        {json_library_wrapper, json_library} = Protox.JsonLibrary.get_library(opts, :encode)
        Protox.JsonEncode.encode!(msg, &json_library_wrapper.encode!(json_library, &1))
      end
    )

    []

    (
      @spec fields_defs() :: list(Protox.Field.t())
      def fields_defs() do
        [
          %{
            __struct__: Protox.Field,
            json_name: "stringValue",
            kind: {:oneof, :value},
            label: :optional,
            name: :string_value,
            tag: 1,
            type: :string
          },
          %{
            __struct__: Protox.Field,
            json_name: "boolValue",
            kind: {:oneof, :value},
            label: :optional,
            name: :bool_value,
            tag: 2,
            type: :bool
          },
          %{
            __struct__: Protox.Field,
            json_name: "intValue",
            kind: {:oneof, :value},
            label: :optional,
            name: :int_value,
            tag: 3,
            type: :int64
          },
          %{
            __struct__: Protox.Field,
            json_name: "doubleValue",
            kind: {:oneof, :value},
            label: :optional,
            name: :double_value,
            tag: 4,
            type: :double
          },
          %{
            __struct__: Protox.Field,
            json_name: "arrayValue",
            kind: {:oneof, :value},
            label: :optional,
            name: :array_value,
            tag: 5,
            type: {:message, Opentelemetry.Proto.Common.V1.ArrayValue}
          },
          %{
            __struct__: Protox.Field,
            json_name: "kvlistValue",
            kind: {:oneof, :value},
            label: :optional,
            name: :kvlist_value,
            tag: 6,
            type: {:message, Opentelemetry.Proto.Common.V1.KeyValueList}
          },
          %{
            __struct__: Protox.Field,
            json_name: "bytesValue",
            kind: {:oneof, :value},
            label: :optional,
            name: :bytes_value,
            tag: 7,
            type: :bytes
          }
        ]
      end

      [
        @spec(field_def(atom) :: {:ok, Protox.Field.t()} | {:error, :no_such_field}),
        (
          def field_def(:string_value) do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "stringValue",
               kind: {:oneof, :value},
               label: :optional,
               name: :string_value,
               tag: 1,
               type: :string
             }}
          end

          def field_def("stringValue") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "stringValue",
               kind: {:oneof, :value},
               label: :optional,
               name: :string_value,
               tag: 1,
               type: :string
             }}
          end

          def field_def("string_value") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "stringValue",
               kind: {:oneof, :value},
               label: :optional,
               name: :string_value,
               tag: 1,
               type: :string
             }}
          end
        ),
        (
          def field_def(:bool_value) do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "boolValue",
               kind: {:oneof, :value},
               label: :optional,
               name: :bool_value,
               tag: 2,
               type: :bool
             }}
          end

          def field_def("boolValue") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "boolValue",
               kind: {:oneof, :value},
               label: :optional,
               name: :bool_value,
               tag: 2,
               type: :bool
             }}
          end

          def field_def("bool_value") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "boolValue",
               kind: {:oneof, :value},
               label: :optional,
               name: :bool_value,
               tag: 2,
               type: :bool
             }}
          end
        ),
        (
          def field_def(:int_value) do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "intValue",
               kind: {:oneof, :value},
               label: :optional,
               name: :int_value,
               tag: 3,
               type: :int64
             }}
          end

          def field_def("intValue") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "intValue",
               kind: {:oneof, :value},
               label: :optional,
               name: :int_value,
               tag: 3,
               type: :int64
             }}
          end

          def field_def("int_value") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "intValue",
               kind: {:oneof, :value},
               label: :optional,
               name: :int_value,
               tag: 3,
               type: :int64
             }}
          end
        ),
        (
          def field_def(:double_value) do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "doubleValue",
               kind: {:oneof, :value},
               label: :optional,
               name: :double_value,
               tag: 4,
               type: :double
             }}
          end

          def field_def("doubleValue") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "doubleValue",
               kind: {:oneof, :value},
               label: :optional,
               name: :double_value,
               tag: 4,
               type: :double
             }}
          end

          def field_def("double_value") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "doubleValue",
               kind: {:oneof, :value},
               label: :optional,
               name: :double_value,
               tag: 4,
               type: :double
             }}
          end
        ),
        (
          def field_def(:array_value) do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "arrayValue",
               kind: {:oneof, :value},
               label: :optional,
               name: :array_value,
               tag: 5,
               type: {:message, Opentelemetry.Proto.Common.V1.ArrayValue}
             }}
          end

          def field_def("arrayValue") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "arrayValue",
               kind: {:oneof, :value},
               label: :optional,
               name: :array_value,
               tag: 5,
               type: {:message, Opentelemetry.Proto.Common.V1.ArrayValue}
             }}
          end

          def field_def("array_value") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "arrayValue",
               kind: {:oneof, :value},
               label: :optional,
               name: :array_value,
               tag: 5,
               type: {:message, Opentelemetry.Proto.Common.V1.ArrayValue}
             }}
          end
        ),
        (
          def field_def(:kvlist_value) do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "kvlistValue",
               kind: {:oneof, :value},
               label: :optional,
               name: :kvlist_value,
               tag: 6,
               type: {:message, Opentelemetry.Proto.Common.V1.KeyValueList}
             }}
          end

          def field_def("kvlistValue") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "kvlistValue",
               kind: {:oneof, :value},
               label: :optional,
               name: :kvlist_value,
               tag: 6,
               type: {:message, Opentelemetry.Proto.Common.V1.KeyValueList}
             }}
          end

          def field_def("kvlist_value") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "kvlistValue",
               kind: {:oneof, :value},
               label: :optional,
               name: :kvlist_value,
               tag: 6,
               type: {:message, Opentelemetry.Proto.Common.V1.KeyValueList}
             }}
          end
        ),
        (
          def field_def(:bytes_value) do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "bytesValue",
               kind: {:oneof, :value},
               label: :optional,
               name: :bytes_value,
               tag: 7,
               type: :bytes
             }}
          end

          def field_def("bytesValue") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "bytesValue",
               kind: {:oneof, :value},
               label: :optional,
               name: :bytes_value,
               tag: 7,
               type: :bytes
             }}
          end

          def field_def("bytes_value") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "bytesValue",
               kind: {:oneof, :value},
               label: :optional,
               name: :bytes_value,
               tag: 7,
               type: :bytes
             }}
          end
        ),
        def field_def(_) do
          {:error, :no_such_field}
        end
      ]
    )

    []

    (
      @spec required_fields() :: []
      def required_fields() do
        []
      end
    )

    (
      @spec syntax() :: atom()
      def syntax() do
        :proto3
      end
    )

    [
      @spec(default(atom) :: {:ok, boolean | integer | String.t() | float} | {:error, atom}),
      def default(:string_value) do
        {:error, :no_default_value}
      end,
      def default(:bool_value) do
        {:error, :no_default_value}
      end,
      def default(:int_value) do
        {:error, :no_default_value}
      end,
      def default(:double_value) do
        {:error, :no_default_value}
      end,
      def default(:array_value) do
        {:error, :no_default_value}
      end,
      def default(:kvlist_value) do
        {:error, :no_default_value}
      end,
      def default(:bytes_value) do
        {:error, :no_default_value}
      end,
      def default(_) do
        {:error, :no_such_field}
      end
    ]

    (
      @spec file_options() :: struct()
      def file_options() do
        file_options = %{
          __struct__: Protox.Google.Protobuf.FileOptions,
          __uf__: [],
          cc_enable_arenas: nil,
          cc_generic_services: nil,
          csharp_namespace: "OpenTelemetry.Proto.Common.V1",
          deprecated: nil,
          go_package: "go.opentelemetry.io/proto/otlp/common/v1",
          java_generate_equals_and_hash: nil,
          java_generic_services: nil,
          java_multiple_files: true,
          java_outer_classname: "CommonProto",
          java_package: "io.opentelemetry.proto.common.v1",
          java_string_check_utf8: nil,
          objc_class_prefix: nil,
          optimize_for: nil,
          php_class_prefix: nil,
          php_generic_services: nil,
          php_metadata_namespace: nil,
          php_namespace: nil,
          py_generic_services: nil,
          ruby_package: nil,
          swift_prefix: nil,
          uninterpreted_option: []
        }

        case function_exported?(Google.Protobuf.FileOptions, :decode!, 1) do
          true ->
            bytes =
              file_options
              |> Protox.Google.Protobuf.FileOptions.encode!()
              |> :binary.list_to_bin()

            apply(Google.Protobuf.FileOptions, :decode!, [bytes])

          false ->
            file_options
        end
      end
    )
  end,
  defmodule Opentelemetry.Proto.Common.V1.ArrayValue do
    @moduledoc false
    defstruct values: []

    (
      (
        @spec encode(struct) :: {:ok, iodata} | {:error, any}
        def encode(msg) do
          try do
            {:ok, encode!(msg)}
          rescue
            e in [Protox.EncodingError, Protox.RequiredFieldsError] -> {:error, e}
          end
        end

        @spec encode!(struct) :: iodata | no_return
        def encode!(msg) do
          [] |> encode_values(msg)
        end
      )

      []

      [
        defp encode_values(acc, msg) do
          try do
            case msg.values do
              [] ->
                acc

              values ->
                [
                  acc,
                  Enum.reduce(values, [], fn value, acc ->
                    [acc, "\n", Protox.Encode.encode_message(value)]
                  end)
                ]
            end
          rescue
            ArgumentError ->
              reraise Protox.EncodingError.new(:values, "invalid field value"), __STACKTRACE__
          end
        end
      ]

      []
    )

    (
      (
        @spec decode(binary) :: {:ok, struct} | {:error, any}
        def decode(bytes) do
          try do
            {:ok, decode!(bytes)}
          rescue
            e in [Protox.DecodingError, Protox.IllegalTagError, Protox.RequiredFieldsError] ->
              {:error, e}
          end
        end

        (
          @spec decode!(binary) :: struct | no_return
          def decode!(bytes) do
            parse_key_value(bytes, struct(Opentelemetry.Proto.Common.V1.ArrayValue))
          end
        )
      )

      (
        @spec parse_key_value(binary, struct) :: struct
        defp parse_key_value(<<>>, msg) do
          msg
        end

        defp parse_key_value(bytes, msg) do
          {field, rest} =
            case Protox.Decode.parse_key(bytes) do
              {0, _, _} ->
                raise %Protox.IllegalTagError{}

              {1, _, bytes} ->
                {len, bytes} = Protox.Varint.decode(bytes)
                {delimited, rest} = Protox.Decode.parse_delimited(bytes, len)

                {[
                   values:
                     msg.values ++ [Opentelemetry.Proto.Common.V1.AnyValue.decode!(delimited)]
                 ], rest}

              {tag, wire_type, rest} ->
                {_, rest} = Protox.Decode.parse_unknown(tag, wire_type, rest)
                {[], rest}
            end

          msg_updated = struct(msg, field)
          parse_key_value(rest, msg_updated)
        end
      )

      []
    )

    (
      @spec json_decode(iodata(), keyword()) :: {:ok, struct()} | {:error, any()}
      def json_decode(input, opts \\ []) do
        try do
          {:ok, json_decode!(input, opts)}
        rescue
          e in Protox.JsonDecodingError -> {:error, e}
        end
      end

      @spec json_decode!(iodata(), keyword()) :: struct() | no_return()
      def json_decode!(input, opts \\ []) do
        {json_library_wrapper, json_library} = Protox.JsonLibrary.get_library(opts, :decode)

        Protox.JsonDecode.decode!(
          input,
          Opentelemetry.Proto.Common.V1.ArrayValue,
          &json_library_wrapper.decode!(json_library, &1)
        )
      end

      @spec json_encode(struct(), keyword()) :: {:ok, iodata()} | {:error, any()}
      def json_encode(msg, opts \\ []) do
        try do
          {:ok, json_encode!(msg, opts)}
        rescue
          e in Protox.JsonEncodingError -> {:error, e}
        end
      end

      @spec json_encode!(struct(), keyword()) :: iodata() | no_return()
      def json_encode!(msg, opts \\ []) do
        {json_library_wrapper, json_library} = Protox.JsonLibrary.get_library(opts, :encode)
        Protox.JsonEncode.encode!(msg, &json_library_wrapper.encode!(json_library, &1))
      end
    )

    []

    (
      @spec fields_defs() :: list(Protox.Field.t())
      def fields_defs() do
        [
          %{
            __struct__: Protox.Field,
            json_name: "values",
            kind: :unpacked,
            label: :repeated,
            name: :values,
            tag: 1,
            type: {:message, Opentelemetry.Proto.Common.V1.AnyValue}
          }
        ]
      end

      [
        @spec(field_def(atom) :: {:ok, Protox.Field.t()} | {:error, :no_such_field}),
        (
          def field_def(:values) do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "values",
               kind: :unpacked,
               label: :repeated,
               name: :values,
               tag: 1,
               type: {:message, Opentelemetry.Proto.Common.V1.AnyValue}
             }}
          end

          def field_def("values") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "values",
               kind: :unpacked,
               label: :repeated,
               name: :values,
               tag: 1,
               type: {:message, Opentelemetry.Proto.Common.V1.AnyValue}
             }}
          end

          []
        ),
        def field_def(_) do
          {:error, :no_such_field}
        end
      ]
    )

    []

    (
      @spec required_fields() :: []
      def required_fields() do
        []
      end
    )

    (
      @spec syntax() :: atom()
      def syntax() do
        :proto3
      end
    )

    [
      @spec(default(atom) :: {:ok, boolean | integer | String.t() | float} | {:error, atom}),
      def default(:values) do
        {:error, :no_default_value}
      end,
      def default(_) do
        {:error, :no_such_field}
      end
    ]

    (
      @spec file_options() :: struct()
      def file_options() do
        file_options = %{
          __struct__: Protox.Google.Protobuf.FileOptions,
          __uf__: [],
          cc_enable_arenas: nil,
          cc_generic_services: nil,
          csharp_namespace: "OpenTelemetry.Proto.Common.V1",
          deprecated: nil,
          go_package: "go.opentelemetry.io/proto/otlp/common/v1",
          java_generate_equals_and_hash: nil,
          java_generic_services: nil,
          java_multiple_files: true,
          java_outer_classname: "CommonProto",
          java_package: "io.opentelemetry.proto.common.v1",
          java_string_check_utf8: nil,
          objc_class_prefix: nil,
          optimize_for: nil,
          php_class_prefix: nil,
          php_generic_services: nil,
          php_metadata_namespace: nil,
          php_namespace: nil,
          py_generic_services: nil,
          ruby_package: nil,
          swift_prefix: nil,
          uninterpreted_option: []
        }

        case function_exported?(Google.Protobuf.FileOptions, :decode!, 1) do
          true ->
            bytes =
              file_options
              |> Protox.Google.Protobuf.FileOptions.encode!()
              |> :binary.list_to_bin()

            apply(Google.Protobuf.FileOptions, :decode!, [bytes])

          false ->
            file_options
        end
      end
    )
  end,
  defmodule Opentelemetry.Proto.Common.V1.InstrumentationScope do
    @moduledoc false
    defstruct name: "", version: "", attributes: [], dropped_attributes_count: 0

    (
      (
        @spec encode(struct) :: {:ok, iodata} | {:error, any}
        def encode(msg) do
          try do
            {:ok, encode!(msg)}
          rescue
            e in [Protox.EncodingError, Protox.RequiredFieldsError] -> {:error, e}
          end
        end

        @spec encode!(struct) :: iodata | no_return
        def encode!(msg) do
          []
          |> encode_name(msg)
          |> encode_version(msg)
          |> encode_attributes(msg)
          |> encode_dropped_attributes_count(msg)
        end
      )

      []

      [
        defp encode_name(acc, msg) do
          try do
            if msg.name == "" do
              acc
            else
              [acc, "\n", Protox.Encode.encode_string(msg.name)]
            end
          rescue
            ArgumentError ->
              reraise Protox.EncodingError.new(:name, "invalid field value"), __STACKTRACE__
          end
        end,
        defp encode_version(acc, msg) do
          try do
            if msg.version == "" do
              acc
            else
              [acc, "\x12", Protox.Encode.encode_string(msg.version)]
            end
          rescue
            ArgumentError ->
              reraise Protox.EncodingError.new(:version, "invalid field value"), __STACKTRACE__
          end
        end,
        defp encode_attributes(acc, msg) do
          try do
            case msg.attributes do
              [] ->
                acc

              values ->
                [
                  acc,
                  Enum.reduce(values, [], fn value, acc ->
                    [acc, "\x1A", Protox.Encode.encode_message(value)]
                  end)
                ]
            end
          rescue
            ArgumentError ->
              reraise Protox.EncodingError.new(:attributes, "invalid field value"), __STACKTRACE__
          end
        end,
        defp encode_dropped_attributes_count(acc, msg) do
          try do
            if msg.dropped_attributes_count == 0 do
              acc
            else
              [acc, " ", Protox.Encode.encode_uint32(msg.dropped_attributes_count)]
            end
          rescue
            ArgumentError ->
              reraise Protox.EncodingError.new(:dropped_attributes_count, "invalid field value"),
                      __STACKTRACE__
          end
        end
      ]

      []
    )

    (
      (
        @spec decode(binary) :: {:ok, struct} | {:error, any}
        def decode(bytes) do
          try do
            {:ok, decode!(bytes)}
          rescue
            e in [Protox.DecodingError, Protox.IllegalTagError, Protox.RequiredFieldsError] ->
              {:error, e}
          end
        end

        (
          @spec decode!(binary) :: struct | no_return
          def decode!(bytes) do
            parse_key_value(bytes, struct(Opentelemetry.Proto.Common.V1.InstrumentationScope))
          end
        )
      )

      (
        @spec parse_key_value(binary, struct) :: struct
        defp parse_key_value(<<>>, msg) do
          msg
        end

        defp parse_key_value(bytes, msg) do
          {field, rest} =
            case Protox.Decode.parse_key(bytes) do
              {0, _, _} ->
                raise %Protox.IllegalTagError{}

              {1, _, bytes} ->
                {len, bytes} = Protox.Varint.decode(bytes)
                {delimited, rest} = Protox.Decode.parse_delimited(bytes, len)
                {[name: delimited], rest}

              {2, _, bytes} ->
                {len, bytes} = Protox.Varint.decode(bytes)
                {delimited, rest} = Protox.Decode.parse_delimited(bytes, len)
                {[version: delimited], rest}

              {3, _, bytes} ->
                {len, bytes} = Protox.Varint.decode(bytes)
                {delimited, rest} = Protox.Decode.parse_delimited(bytes, len)

                {[
                   attributes:
                     msg.attributes ++ [Opentelemetry.Proto.Common.V1.KeyValue.decode!(delimited)]
                 ], rest}

              {4, _, bytes} ->
                {value, rest} = Protox.Decode.parse_uint32(bytes)
                {[dropped_attributes_count: value], rest}

              {tag, wire_type, rest} ->
                {_, rest} = Protox.Decode.parse_unknown(tag, wire_type, rest)
                {[], rest}
            end

          msg_updated = struct(msg, field)
          parse_key_value(rest, msg_updated)
        end
      )

      []
    )

    (
      @spec json_decode(iodata(), keyword()) :: {:ok, struct()} | {:error, any()}
      def json_decode(input, opts \\ []) do
        try do
          {:ok, json_decode!(input, opts)}
        rescue
          e in Protox.JsonDecodingError -> {:error, e}
        end
      end

      @spec json_decode!(iodata(), keyword()) :: struct() | no_return()
      def json_decode!(input, opts \\ []) do
        {json_library_wrapper, json_library} = Protox.JsonLibrary.get_library(opts, :decode)

        Protox.JsonDecode.decode!(
          input,
          Opentelemetry.Proto.Common.V1.InstrumentationScope,
          &json_library_wrapper.decode!(json_library, &1)
        )
      end

      @spec json_encode(struct(), keyword()) :: {:ok, iodata()} | {:error, any()}
      def json_encode(msg, opts \\ []) do
        try do
          {:ok, json_encode!(msg, opts)}
        rescue
          e in Protox.JsonEncodingError -> {:error, e}
        end
      end

      @spec json_encode!(struct(), keyword()) :: iodata() | no_return()
      def json_encode!(msg, opts \\ []) do
        {json_library_wrapper, json_library} = Protox.JsonLibrary.get_library(opts, :encode)
        Protox.JsonEncode.encode!(msg, &json_library_wrapper.encode!(json_library, &1))
      end
    )

    []

    (
      @spec fields_defs() :: list(Protox.Field.t())
      def fields_defs() do
        [
          %{
            __struct__: Protox.Field,
            json_name: "name",
            kind: {:scalar, ""},
            label: :optional,
            name: :name,
            tag: 1,
            type: :string
          },
          %{
            __struct__: Protox.Field,
            json_name: "version",
            kind: {:scalar, ""},
            label: :optional,
            name: :version,
            tag: 2,
            type: :string
          },
          %{
            __struct__: Protox.Field,
            json_name: "attributes",
            kind: :unpacked,
            label: :repeated,
            name: :attributes,
            tag: 3,
            type: {:message, Opentelemetry.Proto.Common.V1.KeyValue}
          },
          %{
            __struct__: Protox.Field,
            json_name: "droppedAttributesCount",
            kind: {:scalar, 0},
            label: :optional,
            name: :dropped_attributes_count,
            tag: 4,
            type: :uint32
          }
        ]
      end

      [
        @spec(field_def(atom) :: {:ok, Protox.Field.t()} | {:error, :no_such_field}),
        (
          def field_def(:name) do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "name",
               kind: {:scalar, ""},
               label: :optional,
               name: :name,
               tag: 1,
               type: :string
             }}
          end

          def field_def("name") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "name",
               kind: {:scalar, ""},
               label: :optional,
               name: :name,
               tag: 1,
               type: :string
             }}
          end

          []
        ),
        (
          def field_def(:version) do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "version",
               kind: {:scalar, ""},
               label: :optional,
               name: :version,
               tag: 2,
               type: :string
             }}
          end

          def field_def("version") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "version",
               kind: {:scalar, ""},
               label: :optional,
               name: :version,
               tag: 2,
               type: :string
             }}
          end

          []
        ),
        (
          def field_def(:attributes) do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "attributes",
               kind: :unpacked,
               label: :repeated,
               name: :attributes,
               tag: 3,
               type: {:message, Opentelemetry.Proto.Common.V1.KeyValue}
             }}
          end

          def field_def("attributes") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "attributes",
               kind: :unpacked,
               label: :repeated,
               name: :attributes,
               tag: 3,
               type: {:message, Opentelemetry.Proto.Common.V1.KeyValue}
             }}
          end

          []
        ),
        (
          def field_def(:dropped_attributes_count) do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "droppedAttributesCount",
               kind: {:scalar, 0},
               label: :optional,
               name: :dropped_attributes_count,
               tag: 4,
               type: :uint32
             }}
          end

          def field_def("droppedAttributesCount") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "droppedAttributesCount",
               kind: {:scalar, 0},
               label: :optional,
               name: :dropped_attributes_count,
               tag: 4,
               type: :uint32
             }}
          end

          def field_def("dropped_attributes_count") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "droppedAttributesCount",
               kind: {:scalar, 0},
               label: :optional,
               name: :dropped_attributes_count,
               tag: 4,
               type: :uint32
             }}
          end
        ),
        def field_def(_) do
          {:error, :no_such_field}
        end
      ]
    )

    []

    (
      @spec required_fields() :: []
      def required_fields() do
        []
      end
    )

    (
      @spec syntax() :: atom()
      def syntax() do
        :proto3
      end
    )

    [
      @spec(default(atom) :: {:ok, boolean | integer | String.t() | float} | {:error, atom}),
      def default(:name) do
        {:ok, ""}
      end,
      def default(:version) do
        {:ok, ""}
      end,
      def default(:attributes) do
        {:error, :no_default_value}
      end,
      def default(:dropped_attributes_count) do
        {:ok, 0}
      end,
      def default(_) do
        {:error, :no_such_field}
      end
    ]

    (
      @spec file_options() :: struct()
      def file_options() do
        file_options = %{
          __struct__: Protox.Google.Protobuf.FileOptions,
          __uf__: [],
          cc_enable_arenas: nil,
          cc_generic_services: nil,
          csharp_namespace: "OpenTelemetry.Proto.Common.V1",
          deprecated: nil,
          go_package: "go.opentelemetry.io/proto/otlp/common/v1",
          java_generate_equals_and_hash: nil,
          java_generic_services: nil,
          java_multiple_files: true,
          java_outer_classname: "CommonProto",
          java_package: "io.opentelemetry.proto.common.v1",
          java_string_check_utf8: nil,
          objc_class_prefix: nil,
          optimize_for: nil,
          php_class_prefix: nil,
          php_generic_services: nil,
          php_metadata_namespace: nil,
          php_namespace: nil,
          py_generic_services: nil,
          ruby_package: nil,
          swift_prefix: nil,
          uninterpreted_option: []
        }

        case function_exported?(Google.Protobuf.FileOptions, :decode!, 1) do
          true ->
            bytes =
              file_options
              |> Protox.Google.Protobuf.FileOptions.encode!()
              |> :binary.list_to_bin()

            apply(Google.Protobuf.FileOptions, :decode!, [bytes])

          false ->
            file_options
        end
      end
    )
  end,
  defmodule Opentelemetry.Proto.Common.V1.KeyValue do
    @moduledoc false
    defstruct key: "", value: nil

    (
      (
        @spec encode(struct) :: {:ok, iodata} | {:error, any}
        def encode(msg) do
          try do
            {:ok, encode!(msg)}
          rescue
            e in [Protox.EncodingError, Protox.RequiredFieldsError] -> {:error, e}
          end
        end

        @spec encode!(struct) :: iodata | no_return
        def encode!(msg) do
          [] |> encode_key(msg) |> encode_value(msg)
        end
      )

      []

      [
        defp encode_key(acc, msg) do
          try do
            if msg.key == "" do
              acc
            else
              [acc, "\n", Protox.Encode.encode_string(msg.key)]
            end
          rescue
            ArgumentError ->
              reraise Protox.EncodingError.new(:key, "invalid field value"), __STACKTRACE__
          end
        end,
        defp encode_value(acc, msg) do
          try do
            if msg.value == nil do
              acc
            else
              [acc, "\x12", Protox.Encode.encode_message(msg.value)]
            end
          rescue
            ArgumentError ->
              reraise Protox.EncodingError.new(:value, "invalid field value"), __STACKTRACE__
          end
        end
      ]

      []
    )

    (
      (
        @spec decode(binary) :: {:ok, struct} | {:error, any}
        def decode(bytes) do
          try do
            {:ok, decode!(bytes)}
          rescue
            e in [Protox.DecodingError, Protox.IllegalTagError, Protox.RequiredFieldsError] ->
              {:error, e}
          end
        end

        (
          @spec decode!(binary) :: struct | no_return
          def decode!(bytes) do
            parse_key_value(bytes, struct(Opentelemetry.Proto.Common.V1.KeyValue))
          end
        )
      )

      (
        @spec parse_key_value(binary, struct) :: struct
        defp parse_key_value(<<>>, msg) do
          msg
        end

        defp parse_key_value(bytes, msg) do
          {field, rest} =
            case Protox.Decode.parse_key(bytes) do
              {0, _, _} ->
                raise %Protox.IllegalTagError{}

              {1, _, bytes} ->
                {len, bytes} = Protox.Varint.decode(bytes)
                {delimited, rest} = Protox.Decode.parse_delimited(bytes, len)
                {[key: delimited], rest}

              {2, _, bytes} ->
                {len, bytes} = Protox.Varint.decode(bytes)
                {delimited, rest} = Protox.Decode.parse_delimited(bytes, len)

                {[
                   value:
                     Protox.MergeMessage.merge(
                       msg.value,
                       Opentelemetry.Proto.Common.V1.AnyValue.decode!(delimited)
                     )
                 ], rest}

              {tag, wire_type, rest} ->
                {_, rest} = Protox.Decode.parse_unknown(tag, wire_type, rest)
                {[], rest}
            end

          msg_updated = struct(msg, field)
          parse_key_value(rest, msg_updated)
        end
      )

      []
    )

    (
      @spec json_decode(iodata(), keyword()) :: {:ok, struct()} | {:error, any()}
      def json_decode(input, opts \\ []) do
        try do
          {:ok, json_decode!(input, opts)}
        rescue
          e in Protox.JsonDecodingError -> {:error, e}
        end
      end

      @spec json_decode!(iodata(), keyword()) :: struct() | no_return()
      def json_decode!(input, opts \\ []) do
        {json_library_wrapper, json_library} = Protox.JsonLibrary.get_library(opts, :decode)

        Protox.JsonDecode.decode!(
          input,
          Opentelemetry.Proto.Common.V1.KeyValue,
          &json_library_wrapper.decode!(json_library, &1)
        )
      end

      @spec json_encode(struct(), keyword()) :: {:ok, iodata()} | {:error, any()}
      def json_encode(msg, opts \\ []) do
        try do
          {:ok, json_encode!(msg, opts)}
        rescue
          e in Protox.JsonEncodingError -> {:error, e}
        end
      end

      @spec json_encode!(struct(), keyword()) :: iodata() | no_return()
      def json_encode!(msg, opts \\ []) do
        {json_library_wrapper, json_library} = Protox.JsonLibrary.get_library(opts, :encode)
        Protox.JsonEncode.encode!(msg, &json_library_wrapper.encode!(json_library, &1))
      end
    )

    []

    (
      @spec fields_defs() :: list(Protox.Field.t())
      def fields_defs() do
        [
          %{
            __struct__: Protox.Field,
            json_name: "key",
            kind: {:scalar, ""},
            label: :optional,
            name: :key,
            tag: 1,
            type: :string
          },
          %{
            __struct__: Protox.Field,
            json_name: "value",
            kind: {:scalar, nil},
            label: :optional,
            name: :value,
            tag: 2,
            type: {:message, Opentelemetry.Proto.Common.V1.AnyValue}
          }
        ]
      end

      [
        @spec(field_def(atom) :: {:ok, Protox.Field.t()} | {:error, :no_such_field}),
        (
          def field_def(:key) do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "key",
               kind: {:scalar, ""},
               label: :optional,
               name: :key,
               tag: 1,
               type: :string
             }}
          end

          def field_def("key") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "key",
               kind: {:scalar, ""},
               label: :optional,
               name: :key,
               tag: 1,
               type: :string
             }}
          end

          []
        ),
        (
          def field_def(:value) do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "value",
               kind: {:scalar, nil},
               label: :optional,
               name: :value,
               tag: 2,
               type: {:message, Opentelemetry.Proto.Common.V1.AnyValue}
             }}
          end

          def field_def("value") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "value",
               kind: {:scalar, nil},
               label: :optional,
               name: :value,
               tag: 2,
               type: {:message, Opentelemetry.Proto.Common.V1.AnyValue}
             }}
          end

          []
        ),
        def field_def(_) do
          {:error, :no_such_field}
        end
      ]
    )

    []

    (
      @spec required_fields() :: []
      def required_fields() do
        []
      end
    )

    (
      @spec syntax() :: atom()
      def syntax() do
        :proto3
      end
    )

    [
      @spec(default(atom) :: {:ok, boolean | integer | String.t() | float} | {:error, atom}),
      def default(:key) do
        {:ok, ""}
      end,
      def default(:value) do
        {:ok, nil}
      end,
      def default(_) do
        {:error, :no_such_field}
      end
    ]

    (
      @spec file_options() :: struct()
      def file_options() do
        file_options = %{
          __struct__: Protox.Google.Protobuf.FileOptions,
          __uf__: [],
          cc_enable_arenas: nil,
          cc_generic_services: nil,
          csharp_namespace: "OpenTelemetry.Proto.Common.V1",
          deprecated: nil,
          go_package: "go.opentelemetry.io/proto/otlp/common/v1",
          java_generate_equals_and_hash: nil,
          java_generic_services: nil,
          java_multiple_files: true,
          java_outer_classname: "CommonProto",
          java_package: "io.opentelemetry.proto.common.v1",
          java_string_check_utf8: nil,
          objc_class_prefix: nil,
          optimize_for: nil,
          php_class_prefix: nil,
          php_generic_services: nil,
          php_metadata_namespace: nil,
          php_namespace: nil,
          py_generic_services: nil,
          ruby_package: nil,
          swift_prefix: nil,
          uninterpreted_option: []
        }

        case function_exported?(Google.Protobuf.FileOptions, :decode!, 1) do
          true ->
            bytes =
              file_options
              |> Protox.Google.Protobuf.FileOptions.encode!()
              |> :binary.list_to_bin()

            apply(Google.Protobuf.FileOptions, :decode!, [bytes])

          false ->
            file_options
        end
      end
    )
  end,
  defmodule Opentelemetry.Proto.Common.V1.KeyValueList do
    @moduledoc false
    defstruct values: []

    (
      (
        @spec encode(struct) :: {:ok, iodata} | {:error, any}
        def encode(msg) do
          try do
            {:ok, encode!(msg)}
          rescue
            e in [Protox.EncodingError, Protox.RequiredFieldsError] -> {:error, e}
          end
        end

        @spec encode!(struct) :: iodata | no_return
        def encode!(msg) do
          [] |> encode_values(msg)
        end
      )

      []

      [
        defp encode_values(acc, msg) do
          try do
            case msg.values do
              [] ->
                acc

              values ->
                [
                  acc,
                  Enum.reduce(values, [], fn value, acc ->
                    [acc, "\n", Protox.Encode.encode_message(value)]
                  end)
                ]
            end
          rescue
            ArgumentError ->
              reraise Protox.EncodingError.new(:values, "invalid field value"), __STACKTRACE__
          end
        end
      ]

      []
    )

    (
      (
        @spec decode(binary) :: {:ok, struct} | {:error, any}
        def decode(bytes) do
          try do
            {:ok, decode!(bytes)}
          rescue
            e in [Protox.DecodingError, Protox.IllegalTagError, Protox.RequiredFieldsError] ->
              {:error, e}
          end
        end

        (
          @spec decode!(binary) :: struct | no_return
          def decode!(bytes) do
            parse_key_value(bytes, struct(Opentelemetry.Proto.Common.V1.KeyValueList))
          end
        )
      )

      (
        @spec parse_key_value(binary, struct) :: struct
        defp parse_key_value(<<>>, msg) do
          msg
        end

        defp parse_key_value(bytes, msg) do
          {field, rest} =
            case Protox.Decode.parse_key(bytes) do
              {0, _, _} ->
                raise %Protox.IllegalTagError{}

              {1, _, bytes} ->
                {len, bytes} = Protox.Varint.decode(bytes)
                {delimited, rest} = Protox.Decode.parse_delimited(bytes, len)

                {[
                   values:
                     msg.values ++ [Opentelemetry.Proto.Common.V1.KeyValue.decode!(delimited)]
                 ], rest}

              {tag, wire_type, rest} ->
                {_, rest} = Protox.Decode.parse_unknown(tag, wire_type, rest)
                {[], rest}
            end

          msg_updated = struct(msg, field)
          parse_key_value(rest, msg_updated)
        end
      )

      []
    )

    (
      @spec json_decode(iodata(), keyword()) :: {:ok, struct()} | {:error, any()}
      def json_decode(input, opts \\ []) do
        try do
          {:ok, json_decode!(input, opts)}
        rescue
          e in Protox.JsonDecodingError -> {:error, e}
        end
      end

      @spec json_decode!(iodata(), keyword()) :: struct() | no_return()
      def json_decode!(input, opts \\ []) do
        {json_library_wrapper, json_library} = Protox.JsonLibrary.get_library(opts, :decode)

        Protox.JsonDecode.decode!(
          input,
          Opentelemetry.Proto.Common.V1.KeyValueList,
          &json_library_wrapper.decode!(json_library, &1)
        )
      end

      @spec json_encode(struct(), keyword()) :: {:ok, iodata()} | {:error, any()}
      def json_encode(msg, opts \\ []) do
        try do
          {:ok, json_encode!(msg, opts)}
        rescue
          e in Protox.JsonEncodingError -> {:error, e}
        end
      end

      @spec json_encode!(struct(), keyword()) :: iodata() | no_return()
      def json_encode!(msg, opts \\ []) do
        {json_library_wrapper, json_library} = Protox.JsonLibrary.get_library(opts, :encode)
        Protox.JsonEncode.encode!(msg, &json_library_wrapper.encode!(json_library, &1))
      end
    )

    []

    (
      @spec fields_defs() :: list(Protox.Field.t())
      def fields_defs() do
        [
          %{
            __struct__: Protox.Field,
            json_name: "values",
            kind: :unpacked,
            label: :repeated,
            name: :values,
            tag: 1,
            type: {:message, Opentelemetry.Proto.Common.V1.KeyValue}
          }
        ]
      end

      [
        @spec(field_def(atom) :: {:ok, Protox.Field.t()} | {:error, :no_such_field}),
        (
          def field_def(:values) do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "values",
               kind: :unpacked,
               label: :repeated,
               name: :values,
               tag: 1,
               type: {:message, Opentelemetry.Proto.Common.V1.KeyValue}
             }}
          end

          def field_def("values") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "values",
               kind: :unpacked,
               label: :repeated,
               name: :values,
               tag: 1,
               type: {:message, Opentelemetry.Proto.Common.V1.KeyValue}
             }}
          end

          []
        ),
        def field_def(_) do
          {:error, :no_such_field}
        end
      ]
    )

    []

    (
      @spec required_fields() :: []
      def required_fields() do
        []
      end
    )

    (
      @spec syntax() :: atom()
      def syntax() do
        :proto3
      end
    )

    [
      @spec(default(atom) :: {:ok, boolean | integer | String.t() | float} | {:error, atom}),
      def default(:values) do
        {:error, :no_default_value}
      end,
      def default(_) do
        {:error, :no_such_field}
      end
    ]

    (
      @spec file_options() :: struct()
      def file_options() do
        file_options = %{
          __struct__: Protox.Google.Protobuf.FileOptions,
          __uf__: [],
          cc_enable_arenas: nil,
          cc_generic_services: nil,
          csharp_namespace: "OpenTelemetry.Proto.Common.V1",
          deprecated: nil,
          go_package: "go.opentelemetry.io/proto/otlp/common/v1",
          java_generate_equals_and_hash: nil,
          java_generic_services: nil,
          java_multiple_files: true,
          java_outer_classname: "CommonProto",
          java_package: "io.opentelemetry.proto.common.v1",
          java_string_check_utf8: nil,
          objc_class_prefix: nil,
          optimize_for: nil,
          php_class_prefix: nil,
          php_generic_services: nil,
          php_metadata_namespace: nil,
          php_namespace: nil,
          py_generic_services: nil,
          ruby_package: nil,
          swift_prefix: nil,
          uninterpreted_option: []
        }

        case function_exported?(Google.Protobuf.FileOptions, :decode!, 1) do
          true ->
            bytes =
              file_options
              |> Protox.Google.Protobuf.FileOptions.encode!()
              |> :binary.list_to_bin()

            apply(Google.Protobuf.FileOptions, :decode!, [bytes])

          false ->
            file_options
        end
      end
    )
  end,
  defmodule Opentelemetry.Proto.Resource.V1.Resource do
    @moduledoc false
    defstruct attributes: [], dropped_attributes_count: 0

    (
      (
        @spec encode(struct) :: {:ok, iodata} | {:error, any}
        def encode(msg) do
          try do
            {:ok, encode!(msg)}
          rescue
            e in [Protox.EncodingError, Protox.RequiredFieldsError] -> {:error, e}
          end
        end

        @spec encode!(struct) :: iodata | no_return
        def encode!(msg) do
          [] |> encode_attributes(msg) |> encode_dropped_attributes_count(msg)
        end
      )

      []

      [
        defp encode_attributes(acc, msg) do
          try do
            case msg.attributes do
              [] ->
                acc

              values ->
                [
                  acc,
                  Enum.reduce(values, [], fn value, acc ->
                    [acc, "\n", Protox.Encode.encode_message(value)]
                  end)
                ]
            end
          rescue
            ArgumentError ->
              reraise Protox.EncodingError.new(:attributes, "invalid field value"), __STACKTRACE__
          end
        end,
        defp encode_dropped_attributes_count(acc, msg) do
          try do
            if msg.dropped_attributes_count == 0 do
              acc
            else
              [acc, "\x10", Protox.Encode.encode_uint32(msg.dropped_attributes_count)]
            end
          rescue
            ArgumentError ->
              reraise Protox.EncodingError.new(:dropped_attributes_count, "invalid field value"),
                      __STACKTRACE__
          end
        end
      ]

      []
    )

    (
      (
        @spec decode(binary) :: {:ok, struct} | {:error, any}
        def decode(bytes) do
          try do
            {:ok, decode!(bytes)}
          rescue
            e in [Protox.DecodingError, Protox.IllegalTagError, Protox.RequiredFieldsError] ->
              {:error, e}
          end
        end

        (
          @spec decode!(binary) :: struct | no_return
          def decode!(bytes) do
            parse_key_value(bytes, struct(Opentelemetry.Proto.Resource.V1.Resource))
          end
        )
      )

      (
        @spec parse_key_value(binary, struct) :: struct
        defp parse_key_value(<<>>, msg) do
          msg
        end

        defp parse_key_value(bytes, msg) do
          {field, rest} =
            case Protox.Decode.parse_key(bytes) do
              {0, _, _} ->
                raise %Protox.IllegalTagError{}

              {1, _, bytes} ->
                {len, bytes} = Protox.Varint.decode(bytes)
                {delimited, rest} = Protox.Decode.parse_delimited(bytes, len)

                {[
                   attributes:
                     msg.attributes ++ [Opentelemetry.Proto.Common.V1.KeyValue.decode!(delimited)]
                 ], rest}

              {2, _, bytes} ->
                {value, rest} = Protox.Decode.parse_uint32(bytes)
                {[dropped_attributes_count: value], rest}

              {tag, wire_type, rest} ->
                {_, rest} = Protox.Decode.parse_unknown(tag, wire_type, rest)
                {[], rest}
            end

          msg_updated = struct(msg, field)
          parse_key_value(rest, msg_updated)
        end
      )

      []
    )

    (
      @spec json_decode(iodata(), keyword()) :: {:ok, struct()} | {:error, any()}
      def json_decode(input, opts \\ []) do
        try do
          {:ok, json_decode!(input, opts)}
        rescue
          e in Protox.JsonDecodingError -> {:error, e}
        end
      end

      @spec json_decode!(iodata(), keyword()) :: struct() | no_return()
      def json_decode!(input, opts \\ []) do
        {json_library_wrapper, json_library} = Protox.JsonLibrary.get_library(opts, :decode)

        Protox.JsonDecode.decode!(
          input,
          Opentelemetry.Proto.Resource.V1.Resource,
          &json_library_wrapper.decode!(json_library, &1)
        )
      end

      @spec json_encode(struct(), keyword()) :: {:ok, iodata()} | {:error, any()}
      def json_encode(msg, opts \\ []) do
        try do
          {:ok, json_encode!(msg, opts)}
        rescue
          e in Protox.JsonEncodingError -> {:error, e}
        end
      end

      @spec json_encode!(struct(), keyword()) :: iodata() | no_return()
      def json_encode!(msg, opts \\ []) do
        {json_library_wrapper, json_library} = Protox.JsonLibrary.get_library(opts, :encode)
        Protox.JsonEncode.encode!(msg, &json_library_wrapper.encode!(json_library, &1))
      end
    )

    []

    (
      @spec fields_defs() :: list(Protox.Field.t())
      def fields_defs() do
        [
          %{
            __struct__: Protox.Field,
            json_name: "attributes",
            kind: :unpacked,
            label: :repeated,
            name: :attributes,
            tag: 1,
            type: {:message, Opentelemetry.Proto.Common.V1.KeyValue}
          },
          %{
            __struct__: Protox.Field,
            json_name: "droppedAttributesCount",
            kind: {:scalar, 0},
            label: :optional,
            name: :dropped_attributes_count,
            tag: 2,
            type: :uint32
          }
        ]
      end

      [
        @spec(field_def(atom) :: {:ok, Protox.Field.t()} | {:error, :no_such_field}),
        (
          def field_def(:attributes) do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "attributes",
               kind: :unpacked,
               label: :repeated,
               name: :attributes,
               tag: 1,
               type: {:message, Opentelemetry.Proto.Common.V1.KeyValue}
             }}
          end

          def field_def("attributes") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "attributes",
               kind: :unpacked,
               label: :repeated,
               name: :attributes,
               tag: 1,
               type: {:message, Opentelemetry.Proto.Common.V1.KeyValue}
             }}
          end

          []
        ),
        (
          def field_def(:dropped_attributes_count) do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "droppedAttributesCount",
               kind: {:scalar, 0},
               label: :optional,
               name: :dropped_attributes_count,
               tag: 2,
               type: :uint32
             }}
          end

          def field_def("droppedAttributesCount") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "droppedAttributesCount",
               kind: {:scalar, 0},
               label: :optional,
               name: :dropped_attributes_count,
               tag: 2,
               type: :uint32
             }}
          end

          def field_def("dropped_attributes_count") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "droppedAttributesCount",
               kind: {:scalar, 0},
               label: :optional,
               name: :dropped_attributes_count,
               tag: 2,
               type: :uint32
             }}
          end
        ),
        def field_def(_) do
          {:error, :no_such_field}
        end
      ]
    )

    []

    (
      @spec required_fields() :: []
      def required_fields() do
        []
      end
    )

    (
      @spec syntax() :: atom()
      def syntax() do
        :proto3
      end
    )

    [
      @spec(default(atom) :: {:ok, boolean | integer | String.t() | float} | {:error, atom}),
      def default(:attributes) do
        {:error, :no_default_value}
      end,
      def default(:dropped_attributes_count) do
        {:ok, 0}
      end,
      def default(_) do
        {:error, :no_such_field}
      end
    ]

    (
      @spec file_options() :: struct()
      def file_options() do
        file_options = %{
          __struct__: Protox.Google.Protobuf.FileOptions,
          __uf__: [],
          cc_enable_arenas: nil,
          cc_generic_services: nil,
          csharp_namespace: "OpenTelemetry.Proto.Resource.V1",
          deprecated: nil,
          go_package: "go.opentelemetry.io/proto/otlp/resource/v1",
          java_generate_equals_and_hash: nil,
          java_generic_services: nil,
          java_multiple_files: true,
          java_outer_classname: "ResourceProto",
          java_package: "io.opentelemetry.proto.resource.v1",
          java_string_check_utf8: nil,
          objc_class_prefix: nil,
          optimize_for: nil,
          php_class_prefix: nil,
          php_generic_services: nil,
          php_metadata_namespace: nil,
          php_namespace: nil,
          py_generic_services: nil,
          ruby_package: nil,
          swift_prefix: nil,
          uninterpreted_option: []
        }

        case function_exported?(Google.Protobuf.FileOptions, :decode!, 1) do
          true ->
            bytes =
              file_options
              |> Protox.Google.Protobuf.FileOptions.encode!()
              |> :binary.list_to_bin()

            apply(Google.Protobuf.FileOptions, :decode!, [bytes])

          false ->
            file_options
        end
      end
    )
  end,
  defmodule Opentelemetry.Proto.Trace.V1.ResourceSpans do
    @moduledoc false
    defstruct resource: nil, scope_spans: [], schema_url: ""

    (
      (
        @spec encode(struct) :: {:ok, iodata} | {:error, any}
        def encode(msg) do
          try do
            {:ok, encode!(msg)}
          rescue
            e in [Protox.EncodingError, Protox.RequiredFieldsError] -> {:error, e}
          end
        end

        @spec encode!(struct) :: iodata | no_return
        def encode!(msg) do
          [] |> encode_resource(msg) |> encode_scope_spans(msg) |> encode_schema_url(msg)
        end
      )

      []

      [
        defp encode_resource(acc, msg) do
          try do
            if msg.resource == nil do
              acc
            else
              [acc, "\n", Protox.Encode.encode_message(msg.resource)]
            end
          rescue
            ArgumentError ->
              reraise Protox.EncodingError.new(:resource, "invalid field value"), __STACKTRACE__
          end
        end,
        defp encode_scope_spans(acc, msg) do
          try do
            case msg.scope_spans do
              [] ->
                acc

              values ->
                [
                  acc,
                  Enum.reduce(values, [], fn value, acc ->
                    [acc, "\x12", Protox.Encode.encode_message(value)]
                  end)
                ]
            end
          rescue
            ArgumentError ->
              reraise Protox.EncodingError.new(:scope_spans, "invalid field value"),
                      __STACKTRACE__
          end
        end,
        defp encode_schema_url(acc, msg) do
          try do
            if msg.schema_url == "" do
              acc
            else
              [acc, "\x1A", Protox.Encode.encode_string(msg.schema_url)]
            end
          rescue
            ArgumentError ->
              reraise Protox.EncodingError.new(:schema_url, "invalid field value"), __STACKTRACE__
          end
        end
      ]

      []
    )

    (
      (
        @spec decode(binary) :: {:ok, struct} | {:error, any}
        def decode(bytes) do
          try do
            {:ok, decode!(bytes)}
          rescue
            e in [Protox.DecodingError, Protox.IllegalTagError, Protox.RequiredFieldsError] ->
              {:error, e}
          end
        end

        (
          @spec decode!(binary) :: struct | no_return
          def decode!(bytes) do
            parse_key_value(bytes, struct(Opentelemetry.Proto.Trace.V1.ResourceSpans))
          end
        )
      )

      (
        @spec parse_key_value(binary, struct) :: struct
        defp parse_key_value(<<>>, msg) do
          msg
        end

        defp parse_key_value(bytes, msg) do
          {field, rest} =
            case Protox.Decode.parse_key(bytes) do
              {0, _, _} ->
                raise %Protox.IllegalTagError{}

              {1, _, bytes} ->
                {len, bytes} = Protox.Varint.decode(bytes)
                {delimited, rest} = Protox.Decode.parse_delimited(bytes, len)

                {[
                   resource:
                     Protox.MergeMessage.merge(
                       msg.resource,
                       Opentelemetry.Proto.Resource.V1.Resource.decode!(delimited)
                     )
                 ], rest}

              {2, _, bytes} ->
                {len, bytes} = Protox.Varint.decode(bytes)
                {delimited, rest} = Protox.Decode.parse_delimited(bytes, len)

                {[
                   scope_spans:
                     msg.scope_spans ++
                       [Opentelemetry.Proto.Trace.V1.ScopeSpans.decode!(delimited)]
                 ], rest}

              {3, _, bytes} ->
                {len, bytes} = Protox.Varint.decode(bytes)
                {delimited, rest} = Protox.Decode.parse_delimited(bytes, len)
                {[schema_url: delimited], rest}

              {tag, wire_type, rest} ->
                {_, rest} = Protox.Decode.parse_unknown(tag, wire_type, rest)
                {[], rest}
            end

          msg_updated = struct(msg, field)
          parse_key_value(rest, msg_updated)
        end
      )

      []
    )

    (
      @spec json_decode(iodata(), keyword()) :: {:ok, struct()} | {:error, any()}
      def json_decode(input, opts \\ []) do
        try do
          {:ok, json_decode!(input, opts)}
        rescue
          e in Protox.JsonDecodingError -> {:error, e}
        end
      end

      @spec json_decode!(iodata(), keyword()) :: struct() | no_return()
      def json_decode!(input, opts \\ []) do
        {json_library_wrapper, json_library} = Protox.JsonLibrary.get_library(opts, :decode)

        Protox.JsonDecode.decode!(
          input,
          Opentelemetry.Proto.Trace.V1.ResourceSpans,
          &json_library_wrapper.decode!(json_library, &1)
        )
      end

      @spec json_encode(struct(), keyword()) :: {:ok, iodata()} | {:error, any()}
      def json_encode(msg, opts \\ []) do
        try do
          {:ok, json_encode!(msg, opts)}
        rescue
          e in Protox.JsonEncodingError -> {:error, e}
        end
      end

      @spec json_encode!(struct(), keyword()) :: iodata() | no_return()
      def json_encode!(msg, opts \\ []) do
        {json_library_wrapper, json_library} = Protox.JsonLibrary.get_library(opts, :encode)
        Protox.JsonEncode.encode!(msg, &json_library_wrapper.encode!(json_library, &1))
      end
    )

    []

    (
      @spec fields_defs() :: list(Protox.Field.t())
      def fields_defs() do
        [
          %{
            __struct__: Protox.Field,
            json_name: "resource",
            kind: {:scalar, nil},
            label: :optional,
            name: :resource,
            tag: 1,
            type: {:message, Opentelemetry.Proto.Resource.V1.Resource}
          },
          %{
            __struct__: Protox.Field,
            json_name: "scopeSpans",
            kind: :unpacked,
            label: :repeated,
            name: :scope_spans,
            tag: 2,
            type: {:message, Opentelemetry.Proto.Trace.V1.ScopeSpans}
          },
          %{
            __struct__: Protox.Field,
            json_name: "schemaUrl",
            kind: {:scalar, ""},
            label: :optional,
            name: :schema_url,
            tag: 3,
            type: :string
          }
        ]
      end

      [
        @spec(field_def(atom) :: {:ok, Protox.Field.t()} | {:error, :no_such_field}),
        (
          def field_def(:resource) do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "resource",
               kind: {:scalar, nil},
               label: :optional,
               name: :resource,
               tag: 1,
               type: {:message, Opentelemetry.Proto.Resource.V1.Resource}
             }}
          end

          def field_def("resource") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "resource",
               kind: {:scalar, nil},
               label: :optional,
               name: :resource,
               tag: 1,
               type: {:message, Opentelemetry.Proto.Resource.V1.Resource}
             }}
          end

          []
        ),
        (
          def field_def(:scope_spans) do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "scopeSpans",
               kind: :unpacked,
               label: :repeated,
               name: :scope_spans,
               tag: 2,
               type: {:message, Opentelemetry.Proto.Trace.V1.ScopeSpans}
             }}
          end

          def field_def("scopeSpans") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "scopeSpans",
               kind: :unpacked,
               label: :repeated,
               name: :scope_spans,
               tag: 2,
               type: {:message, Opentelemetry.Proto.Trace.V1.ScopeSpans}
             }}
          end

          def field_def("scope_spans") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "scopeSpans",
               kind: :unpacked,
               label: :repeated,
               name: :scope_spans,
               tag: 2,
               type: {:message, Opentelemetry.Proto.Trace.V1.ScopeSpans}
             }}
          end
        ),
        (
          def field_def(:schema_url) do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "schemaUrl",
               kind: {:scalar, ""},
               label: :optional,
               name: :schema_url,
               tag: 3,
               type: :string
             }}
          end

          def field_def("schemaUrl") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "schemaUrl",
               kind: {:scalar, ""},
               label: :optional,
               name: :schema_url,
               tag: 3,
               type: :string
             }}
          end

          def field_def("schema_url") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "schemaUrl",
               kind: {:scalar, ""},
               label: :optional,
               name: :schema_url,
               tag: 3,
               type: :string
             }}
          end
        ),
        def field_def(_) do
          {:error, :no_such_field}
        end
      ]
    )

    []

    (
      @spec required_fields() :: []
      def required_fields() do
        []
      end
    )

    (
      @spec syntax() :: atom()
      def syntax() do
        :proto3
      end
    )

    [
      @spec(default(atom) :: {:ok, boolean | integer | String.t() | float} | {:error, atom}),
      def default(:resource) do
        {:ok, nil}
      end,
      def default(:scope_spans) do
        {:error, :no_default_value}
      end,
      def default(:schema_url) do
        {:ok, ""}
      end,
      def default(_) do
        {:error, :no_such_field}
      end
    ]

    (
      @spec file_options() :: struct()
      def file_options() do
        file_options = %{
          __struct__: Protox.Google.Protobuf.FileOptions,
          __uf__: [],
          cc_enable_arenas: nil,
          cc_generic_services: nil,
          csharp_namespace: "OpenTelemetry.Proto.Trace.V1",
          deprecated: nil,
          go_package: "go.opentelemetry.io/proto/otlp/trace/v1",
          java_generate_equals_and_hash: nil,
          java_generic_services: nil,
          java_multiple_files: true,
          java_outer_classname: "TraceProto",
          java_package: "io.opentelemetry.proto.trace.v1",
          java_string_check_utf8: nil,
          objc_class_prefix: nil,
          optimize_for: nil,
          php_class_prefix: nil,
          php_generic_services: nil,
          php_metadata_namespace: nil,
          php_namespace: nil,
          py_generic_services: nil,
          ruby_package: nil,
          swift_prefix: nil,
          uninterpreted_option: []
        }

        case function_exported?(Google.Protobuf.FileOptions, :decode!, 1) do
          true ->
            bytes =
              file_options
              |> Protox.Google.Protobuf.FileOptions.encode!()
              |> :binary.list_to_bin()

            apply(Google.Protobuf.FileOptions, :decode!, [bytes])

          false ->
            file_options
        end
      end
    )
  end,
  defmodule Opentelemetry.Proto.Trace.V1.ScopeSpans do
    @moduledoc false
    defstruct scope: nil, spans: [], schema_url: ""

    (
      (
        @spec encode(struct) :: {:ok, iodata} | {:error, any}
        def encode(msg) do
          try do
            {:ok, encode!(msg)}
          rescue
            e in [Protox.EncodingError, Protox.RequiredFieldsError] -> {:error, e}
          end
        end

        @spec encode!(struct) :: iodata | no_return
        def encode!(msg) do
          [] |> encode_scope(msg) |> encode_spans(msg) |> encode_schema_url(msg)
        end
      )

      []

      [
        defp encode_scope(acc, msg) do
          try do
            if msg.scope == nil do
              acc
            else
              [acc, "\n", Protox.Encode.encode_message(msg.scope)]
            end
          rescue
            ArgumentError ->
              reraise Protox.EncodingError.new(:scope, "invalid field value"), __STACKTRACE__
          end
        end,
        defp encode_spans(acc, msg) do
          try do
            case msg.spans do
              [] ->
                acc

              values ->
                [
                  acc,
                  Enum.reduce(values, [], fn value, acc ->
                    [acc, "\x12", Protox.Encode.encode_message(value)]
                  end)
                ]
            end
          rescue
            ArgumentError ->
              reraise Protox.EncodingError.new(:spans, "invalid field value"), __STACKTRACE__
          end
        end,
        defp encode_schema_url(acc, msg) do
          try do
            if msg.schema_url == "" do
              acc
            else
              [acc, "\x1A", Protox.Encode.encode_string(msg.schema_url)]
            end
          rescue
            ArgumentError ->
              reraise Protox.EncodingError.new(:schema_url, "invalid field value"), __STACKTRACE__
          end
        end
      ]

      []
    )

    (
      (
        @spec decode(binary) :: {:ok, struct} | {:error, any}
        def decode(bytes) do
          try do
            {:ok, decode!(bytes)}
          rescue
            e in [Protox.DecodingError, Protox.IllegalTagError, Protox.RequiredFieldsError] ->
              {:error, e}
          end
        end

        (
          @spec decode!(binary) :: struct | no_return
          def decode!(bytes) do
            parse_key_value(bytes, struct(Opentelemetry.Proto.Trace.V1.ScopeSpans))
          end
        )
      )

      (
        @spec parse_key_value(binary, struct) :: struct
        defp parse_key_value(<<>>, msg) do
          msg
        end

        defp parse_key_value(bytes, msg) do
          {field, rest} =
            case Protox.Decode.parse_key(bytes) do
              {0, _, _} ->
                raise %Protox.IllegalTagError{}

              {1, _, bytes} ->
                {len, bytes} = Protox.Varint.decode(bytes)
                {delimited, rest} = Protox.Decode.parse_delimited(bytes, len)

                {[
                   scope:
                     Protox.MergeMessage.merge(
                       msg.scope,
                       Opentelemetry.Proto.Common.V1.InstrumentationScope.decode!(delimited)
                     )
                 ], rest}

              {2, _, bytes} ->
                {len, bytes} = Protox.Varint.decode(bytes)
                {delimited, rest} = Protox.Decode.parse_delimited(bytes, len)

                {[spans: msg.spans ++ [Opentelemetry.Proto.Trace.V1.Span.decode!(delimited)]],
                 rest}

              {3, _, bytes} ->
                {len, bytes} = Protox.Varint.decode(bytes)
                {delimited, rest} = Protox.Decode.parse_delimited(bytes, len)
                {[schema_url: delimited], rest}

              {tag, wire_type, rest} ->
                {_, rest} = Protox.Decode.parse_unknown(tag, wire_type, rest)
                {[], rest}
            end

          msg_updated = struct(msg, field)
          parse_key_value(rest, msg_updated)
        end
      )

      []
    )

    (
      @spec json_decode(iodata(), keyword()) :: {:ok, struct()} | {:error, any()}
      def json_decode(input, opts \\ []) do
        try do
          {:ok, json_decode!(input, opts)}
        rescue
          e in Protox.JsonDecodingError -> {:error, e}
        end
      end

      @spec json_decode!(iodata(), keyword()) :: struct() | no_return()
      def json_decode!(input, opts \\ []) do
        {json_library_wrapper, json_library} = Protox.JsonLibrary.get_library(opts, :decode)

        Protox.JsonDecode.decode!(
          input,
          Opentelemetry.Proto.Trace.V1.ScopeSpans,
          &json_library_wrapper.decode!(json_library, &1)
        )
      end

      @spec json_encode(struct(), keyword()) :: {:ok, iodata()} | {:error, any()}
      def json_encode(msg, opts \\ []) do
        try do
          {:ok, json_encode!(msg, opts)}
        rescue
          e in Protox.JsonEncodingError -> {:error, e}
        end
      end

      @spec json_encode!(struct(), keyword()) :: iodata() | no_return()
      def json_encode!(msg, opts \\ []) do
        {json_library_wrapper, json_library} = Protox.JsonLibrary.get_library(opts, :encode)
        Protox.JsonEncode.encode!(msg, &json_library_wrapper.encode!(json_library, &1))
      end
    )

    []

    (
      @spec fields_defs() :: list(Protox.Field.t())
      def fields_defs() do
        [
          %{
            __struct__: Protox.Field,
            json_name: "scope",
            kind: {:scalar, nil},
            label: :optional,
            name: :scope,
            tag: 1,
            type: {:message, Opentelemetry.Proto.Common.V1.InstrumentationScope}
          },
          %{
            __struct__: Protox.Field,
            json_name: "spans",
            kind: :unpacked,
            label: :repeated,
            name: :spans,
            tag: 2,
            type: {:message, Opentelemetry.Proto.Trace.V1.Span}
          },
          %{
            __struct__: Protox.Field,
            json_name: "schemaUrl",
            kind: {:scalar, ""},
            label: :optional,
            name: :schema_url,
            tag: 3,
            type: :string
          }
        ]
      end

      [
        @spec(field_def(atom) :: {:ok, Protox.Field.t()} | {:error, :no_such_field}),
        (
          def field_def(:scope) do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "scope",
               kind: {:scalar, nil},
               label: :optional,
               name: :scope,
               tag: 1,
               type: {:message, Opentelemetry.Proto.Common.V1.InstrumentationScope}
             }}
          end

          def field_def("scope") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "scope",
               kind: {:scalar, nil},
               label: :optional,
               name: :scope,
               tag: 1,
               type: {:message, Opentelemetry.Proto.Common.V1.InstrumentationScope}
             }}
          end

          []
        ),
        (
          def field_def(:spans) do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "spans",
               kind: :unpacked,
               label: :repeated,
               name: :spans,
               tag: 2,
               type: {:message, Opentelemetry.Proto.Trace.V1.Span}
             }}
          end

          def field_def("spans") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "spans",
               kind: :unpacked,
               label: :repeated,
               name: :spans,
               tag: 2,
               type: {:message, Opentelemetry.Proto.Trace.V1.Span}
             }}
          end

          []
        ),
        (
          def field_def(:schema_url) do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "schemaUrl",
               kind: {:scalar, ""},
               label: :optional,
               name: :schema_url,
               tag: 3,
               type: :string
             }}
          end

          def field_def("schemaUrl") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "schemaUrl",
               kind: {:scalar, ""},
               label: :optional,
               name: :schema_url,
               tag: 3,
               type: :string
             }}
          end

          def field_def("schema_url") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "schemaUrl",
               kind: {:scalar, ""},
               label: :optional,
               name: :schema_url,
               tag: 3,
               type: :string
             }}
          end
        ),
        def field_def(_) do
          {:error, :no_such_field}
        end
      ]
    )

    []

    (
      @spec required_fields() :: []
      def required_fields() do
        []
      end
    )

    (
      @spec syntax() :: atom()
      def syntax() do
        :proto3
      end
    )

    [
      @spec(default(atom) :: {:ok, boolean | integer | String.t() | float} | {:error, atom}),
      def default(:scope) do
        {:ok, nil}
      end,
      def default(:spans) do
        {:error, :no_default_value}
      end,
      def default(:schema_url) do
        {:ok, ""}
      end,
      def default(_) do
        {:error, :no_such_field}
      end
    ]

    (
      @spec file_options() :: struct()
      def file_options() do
        file_options = %{
          __struct__: Protox.Google.Protobuf.FileOptions,
          __uf__: [],
          cc_enable_arenas: nil,
          cc_generic_services: nil,
          csharp_namespace: "OpenTelemetry.Proto.Trace.V1",
          deprecated: nil,
          go_package: "go.opentelemetry.io/proto/otlp/trace/v1",
          java_generate_equals_and_hash: nil,
          java_generic_services: nil,
          java_multiple_files: true,
          java_outer_classname: "TraceProto",
          java_package: "io.opentelemetry.proto.trace.v1",
          java_string_check_utf8: nil,
          objc_class_prefix: nil,
          optimize_for: nil,
          php_class_prefix: nil,
          php_generic_services: nil,
          php_metadata_namespace: nil,
          php_namespace: nil,
          py_generic_services: nil,
          ruby_package: nil,
          swift_prefix: nil,
          uninterpreted_option: []
        }

        case function_exported?(Google.Protobuf.FileOptions, :decode!, 1) do
          true ->
            bytes =
              file_options
              |> Protox.Google.Protobuf.FileOptions.encode!()
              |> :binary.list_to_bin()

            apply(Google.Protobuf.FileOptions, :decode!, [bytes])

          false ->
            file_options
        end
      end
    )
  end,
  defmodule Opentelemetry.Proto.Trace.V1.Span do
    @moduledoc false
    defstruct trace_id: "",
              span_id: "",
              trace_state: "",
              parent_span_id: "",
              name: "",
              kind: :SPAN_KIND_UNSPECIFIED,
              start_time_unix_nano: 0,
              end_time_unix_nano: 0,
              attributes: [],
              dropped_attributes_count: 0,
              events: [],
              dropped_events_count: 0,
              links: [],
              dropped_links_count: 0,
              status: nil,
              flags: 0

    (
      (
        @spec encode(struct) :: {:ok, iodata} | {:error, any}
        def encode(msg) do
          try do
            {:ok, encode!(msg)}
          rescue
            e in [Protox.EncodingError, Protox.RequiredFieldsError] -> {:error, e}
          end
        end

        @spec encode!(struct) :: iodata | no_return
        def encode!(msg) do
          []
          |> encode_trace_id(msg)
          |> encode_span_id(msg)
          |> encode_trace_state(msg)
          |> encode_parent_span_id(msg)
          |> encode_name(msg)
          |> encode_kind(msg)
          |> encode_start_time_unix_nano(msg)
          |> encode_end_time_unix_nano(msg)
          |> encode_attributes(msg)
          |> encode_dropped_attributes_count(msg)
          |> encode_events(msg)
          |> encode_dropped_events_count(msg)
          |> encode_links(msg)
          |> encode_dropped_links_count(msg)
          |> encode_status(msg)
          |> encode_flags(msg)
        end
      )

      []

      [
        defp encode_trace_id(acc, msg) do
          try do
            if msg.trace_id == "" do
              acc
            else
              [acc, "\n", Protox.Encode.encode_bytes(msg.trace_id)]
            end
          rescue
            ArgumentError ->
              reraise Protox.EncodingError.new(:trace_id, "invalid field value"), __STACKTRACE__
          end
        end,
        defp encode_span_id(acc, msg) do
          try do
            if msg.span_id == "" do
              acc
            else
              [acc, "\x12", Protox.Encode.encode_bytes(msg.span_id)]
            end
          rescue
            ArgumentError ->
              reraise Protox.EncodingError.new(:span_id, "invalid field value"), __STACKTRACE__
          end
        end,
        defp encode_trace_state(acc, msg) do
          try do
            if msg.trace_state == "" do
              acc
            else
              [acc, "\x1A", Protox.Encode.encode_string(msg.trace_state)]
            end
          rescue
            ArgumentError ->
              reraise Protox.EncodingError.new(:trace_state, "invalid field value"),
                      __STACKTRACE__
          end
        end,
        defp encode_parent_span_id(acc, msg) do
          try do
            if msg.parent_span_id == "" do
              acc
            else
              [acc, "\"", Protox.Encode.encode_bytes(msg.parent_span_id)]
            end
          rescue
            ArgumentError ->
              reraise Protox.EncodingError.new(:parent_span_id, "invalid field value"),
                      __STACKTRACE__
          end
        end,
        defp encode_name(acc, msg) do
          try do
            if msg.name == "" do
              acc
            else
              [acc, "*", Protox.Encode.encode_string(msg.name)]
            end
          rescue
            ArgumentError ->
              reraise Protox.EncodingError.new(:name, "invalid field value"), __STACKTRACE__
          end
        end,
        defp encode_kind(acc, msg) do
          try do
            if msg.kind == :SPAN_KIND_UNSPECIFIED do
              acc
            else
              [
                acc,
                "0",
                msg.kind
                |> Opentelemetry.Proto.Trace.V1.Span.SpanKind.encode()
                |> Protox.Encode.encode_enum()
              ]
            end
          rescue
            ArgumentError ->
              reraise Protox.EncodingError.new(:kind, "invalid field value"), __STACKTRACE__
          end
        end,
        defp encode_start_time_unix_nano(acc, msg) do
          try do
            if msg.start_time_unix_nano == 0 do
              acc
            else
              [acc, "9", Protox.Encode.encode_fixed64(msg.start_time_unix_nano)]
            end
          rescue
            ArgumentError ->
              reraise Protox.EncodingError.new(:start_time_unix_nano, "invalid field value"),
                      __STACKTRACE__
          end
        end,
        defp encode_end_time_unix_nano(acc, msg) do
          try do
            if msg.end_time_unix_nano == 0 do
              acc
            else
              [acc, "A", Protox.Encode.encode_fixed64(msg.end_time_unix_nano)]
            end
          rescue
            ArgumentError ->
              reraise Protox.EncodingError.new(:end_time_unix_nano, "invalid field value"),
                      __STACKTRACE__
          end
        end,
        defp encode_attributes(acc, msg) do
          try do
            case msg.attributes do
              [] ->
                acc

              values ->
                [
                  acc,
                  Enum.reduce(values, [], fn value, acc ->
                    [acc, "J", Protox.Encode.encode_message(value)]
                  end)
                ]
            end
          rescue
            ArgumentError ->
              reraise Protox.EncodingError.new(:attributes, "invalid field value"), __STACKTRACE__
          end
        end,
        defp encode_dropped_attributes_count(acc, msg) do
          try do
            if msg.dropped_attributes_count == 0 do
              acc
            else
              [acc, "P", Protox.Encode.encode_uint32(msg.dropped_attributes_count)]
            end
          rescue
            ArgumentError ->
              reraise Protox.EncodingError.new(:dropped_attributes_count, "invalid field value"),
                      __STACKTRACE__
          end
        end,
        defp encode_events(acc, msg) do
          try do
            case msg.events do
              [] ->
                acc

              values ->
                [
                  acc,
                  Enum.reduce(values, [], fn value, acc ->
                    [acc, "Z", Protox.Encode.encode_message(value)]
                  end)
                ]
            end
          rescue
            ArgumentError ->
              reraise Protox.EncodingError.new(:events, "invalid field value"), __STACKTRACE__
          end
        end,
        defp encode_dropped_events_count(acc, msg) do
          try do
            if msg.dropped_events_count == 0 do
              acc
            else
              [acc, "`", Protox.Encode.encode_uint32(msg.dropped_events_count)]
            end
          rescue
            ArgumentError ->
              reraise Protox.EncodingError.new(:dropped_events_count, "invalid field value"),
                      __STACKTRACE__
          end
        end,
        defp encode_links(acc, msg) do
          try do
            case msg.links do
              [] ->
                acc

              values ->
                [
                  acc,
                  Enum.reduce(values, [], fn value, acc ->
                    [acc, "j", Protox.Encode.encode_message(value)]
                  end)
                ]
            end
          rescue
            ArgumentError ->
              reraise Protox.EncodingError.new(:links, "invalid field value"), __STACKTRACE__
          end
        end,
        defp encode_dropped_links_count(acc, msg) do
          try do
            if msg.dropped_links_count == 0 do
              acc
            else
              [acc, "p", Protox.Encode.encode_uint32(msg.dropped_links_count)]
            end
          rescue
            ArgumentError ->
              reraise Protox.EncodingError.new(:dropped_links_count, "invalid field value"),
                      __STACKTRACE__
          end
        end,
        defp encode_status(acc, msg) do
          try do
            if msg.status == nil do
              acc
            else
              [acc, "z", Protox.Encode.encode_message(msg.status)]
            end
          rescue
            ArgumentError ->
              reraise Protox.EncodingError.new(:status, "invalid field value"), __STACKTRACE__
          end
        end,
        defp encode_flags(acc, msg) do
          try do
            if msg.flags == 0 do
              acc
            else
              [acc, "\x85\x01", Protox.Encode.encode_fixed32(msg.flags)]
            end
          rescue
            ArgumentError ->
              reraise Protox.EncodingError.new(:flags, "invalid field value"), __STACKTRACE__
          end
        end
      ]

      []
    )

    (
      (
        @spec decode(binary) :: {:ok, struct} | {:error, any}
        def decode(bytes) do
          try do
            {:ok, decode!(bytes)}
          rescue
            e in [Protox.DecodingError, Protox.IllegalTagError, Protox.RequiredFieldsError] ->
              {:error, e}
          end
        end

        (
          @spec decode!(binary) :: struct | no_return
          def decode!(bytes) do
            parse_key_value(bytes, struct(Opentelemetry.Proto.Trace.V1.Span))
          end
        )
      )

      (
        @spec parse_key_value(binary, struct) :: struct
        defp parse_key_value(<<>>, msg) do
          msg
        end

        defp parse_key_value(bytes, msg) do
          {field, rest} =
            case Protox.Decode.parse_key(bytes) do
              {0, _, _} ->
                raise %Protox.IllegalTagError{}

              {1, _, bytes} ->
                {len, bytes} = Protox.Varint.decode(bytes)
                {delimited, rest} = Protox.Decode.parse_delimited(bytes, len)
                {[trace_id: delimited], rest}

              {2, _, bytes} ->
                {len, bytes} = Protox.Varint.decode(bytes)
                {delimited, rest} = Protox.Decode.parse_delimited(bytes, len)
                {[span_id: delimited], rest}

              {3, _, bytes} ->
                {len, bytes} = Protox.Varint.decode(bytes)
                {delimited, rest} = Protox.Decode.parse_delimited(bytes, len)
                {[trace_state: delimited], rest}

              {4, _, bytes} ->
                {len, bytes} = Protox.Varint.decode(bytes)
                {delimited, rest} = Protox.Decode.parse_delimited(bytes, len)
                {[parent_span_id: delimited], rest}

              {5, _, bytes} ->
                {len, bytes} = Protox.Varint.decode(bytes)
                {delimited, rest} = Protox.Decode.parse_delimited(bytes, len)
                {[name: delimited], rest}

              {6, _, bytes} ->
                {value, rest} =
                  Protox.Decode.parse_enum(bytes, Opentelemetry.Proto.Trace.V1.Span.SpanKind)

                {[kind: value], rest}

              {7, _, bytes} ->
                {value, rest} = Protox.Decode.parse_fixed64(bytes)
                {[start_time_unix_nano: value], rest}

              {8, _, bytes} ->
                {value, rest} = Protox.Decode.parse_fixed64(bytes)
                {[end_time_unix_nano: value], rest}

              {9, _, bytes} ->
                {len, bytes} = Protox.Varint.decode(bytes)
                {delimited, rest} = Protox.Decode.parse_delimited(bytes, len)

                {[
                   attributes:
                     msg.attributes ++ [Opentelemetry.Proto.Common.V1.KeyValue.decode!(delimited)]
                 ], rest}

              {10, _, bytes} ->
                {value, rest} = Protox.Decode.parse_uint32(bytes)
                {[dropped_attributes_count: value], rest}

              {11, _, bytes} ->
                {len, bytes} = Protox.Varint.decode(bytes)
                {delimited, rest} = Protox.Decode.parse_delimited(bytes, len)

                {[
                   events:
                     msg.events ++ [Opentelemetry.Proto.Trace.V1.Span.Event.decode!(delimited)]
                 ], rest}

              {12, _, bytes} ->
                {value, rest} = Protox.Decode.parse_uint32(bytes)
                {[dropped_events_count: value], rest}

              {13, _, bytes} ->
                {len, bytes} = Protox.Varint.decode(bytes)
                {delimited, rest} = Protox.Decode.parse_delimited(bytes, len)

                {[
                   links: msg.links ++ [Opentelemetry.Proto.Trace.V1.Span.Link.decode!(delimited)]
                 ], rest}

              {14, _, bytes} ->
                {value, rest} = Protox.Decode.parse_uint32(bytes)
                {[dropped_links_count: value], rest}

              {15, _, bytes} ->
                {len, bytes} = Protox.Varint.decode(bytes)
                {delimited, rest} = Protox.Decode.parse_delimited(bytes, len)

                {[
                   status:
                     Protox.MergeMessage.merge(
                       msg.status,
                       Opentelemetry.Proto.Trace.V1.Status.decode!(delimited)
                     )
                 ], rest}

              {16, _, bytes} ->
                {value, rest} = Protox.Decode.parse_fixed32(bytes)
                {[flags: value], rest}

              {tag, wire_type, rest} ->
                {_, rest} = Protox.Decode.parse_unknown(tag, wire_type, rest)
                {[], rest}
            end

          msg_updated = struct(msg, field)
          parse_key_value(rest, msg_updated)
        end
      )

      []
    )

    (
      @spec json_decode(iodata(), keyword()) :: {:ok, struct()} | {:error, any()}
      def json_decode(input, opts \\ []) do
        try do
          {:ok, json_decode!(input, opts)}
        rescue
          e in Protox.JsonDecodingError -> {:error, e}
        end
      end

      @spec json_decode!(iodata(), keyword()) :: struct() | no_return()
      def json_decode!(input, opts \\ []) do
        {json_library_wrapper, json_library} = Protox.JsonLibrary.get_library(opts, :decode)

        Protox.JsonDecode.decode!(
          input,
          Opentelemetry.Proto.Trace.V1.Span,
          &json_library_wrapper.decode!(json_library, &1)
        )
      end

      @spec json_encode(struct(), keyword()) :: {:ok, iodata()} | {:error, any()}
      def json_encode(msg, opts \\ []) do
        try do
          {:ok, json_encode!(msg, opts)}
        rescue
          e in Protox.JsonEncodingError -> {:error, e}
        end
      end

      @spec json_encode!(struct(), keyword()) :: iodata() | no_return()
      def json_encode!(msg, opts \\ []) do
        {json_library_wrapper, json_library} = Protox.JsonLibrary.get_library(opts, :encode)
        Protox.JsonEncode.encode!(msg, &json_library_wrapper.encode!(json_library, &1))
      end
    )

    []

    (
      @spec fields_defs() :: list(Protox.Field.t())
      def fields_defs() do
        [
          %{
            __struct__: Protox.Field,
            json_name: "traceId",
            kind: {:scalar, ""},
            label: :optional,
            name: :trace_id,
            tag: 1,
            type: :bytes
          },
          %{
            __struct__: Protox.Field,
            json_name: "spanId",
            kind: {:scalar, ""},
            label: :optional,
            name: :span_id,
            tag: 2,
            type: :bytes
          },
          %{
            __struct__: Protox.Field,
            json_name: "traceState",
            kind: {:scalar, ""},
            label: :optional,
            name: :trace_state,
            tag: 3,
            type: :string
          },
          %{
            __struct__: Protox.Field,
            json_name: "parentSpanId",
            kind: {:scalar, ""},
            label: :optional,
            name: :parent_span_id,
            tag: 4,
            type: :bytes
          },
          %{
            __struct__: Protox.Field,
            json_name: "name",
            kind: {:scalar, ""},
            label: :optional,
            name: :name,
            tag: 5,
            type: :string
          },
          %{
            __struct__: Protox.Field,
            json_name: "kind",
            kind: {:scalar, :SPAN_KIND_UNSPECIFIED},
            label: :optional,
            name: :kind,
            tag: 6,
            type: {:enum, Opentelemetry.Proto.Trace.V1.Span.SpanKind}
          },
          %{
            __struct__: Protox.Field,
            json_name: "startTimeUnixNano",
            kind: {:scalar, 0},
            label: :optional,
            name: :start_time_unix_nano,
            tag: 7,
            type: :fixed64
          },
          %{
            __struct__: Protox.Field,
            json_name: "endTimeUnixNano",
            kind: {:scalar, 0},
            label: :optional,
            name: :end_time_unix_nano,
            tag: 8,
            type: :fixed64
          },
          %{
            __struct__: Protox.Field,
            json_name: "attributes",
            kind: :unpacked,
            label: :repeated,
            name: :attributes,
            tag: 9,
            type: {:message, Opentelemetry.Proto.Common.V1.KeyValue}
          },
          %{
            __struct__: Protox.Field,
            json_name: "droppedAttributesCount",
            kind: {:scalar, 0},
            label: :optional,
            name: :dropped_attributes_count,
            tag: 10,
            type: :uint32
          },
          %{
            __struct__: Protox.Field,
            json_name: "events",
            kind: :unpacked,
            label: :repeated,
            name: :events,
            tag: 11,
            type: {:message, Opentelemetry.Proto.Trace.V1.Span.Event}
          },
          %{
            __struct__: Protox.Field,
            json_name: "droppedEventsCount",
            kind: {:scalar, 0},
            label: :optional,
            name: :dropped_events_count,
            tag: 12,
            type: :uint32
          },
          %{
            __struct__: Protox.Field,
            json_name: "links",
            kind: :unpacked,
            label: :repeated,
            name: :links,
            tag: 13,
            type: {:message, Opentelemetry.Proto.Trace.V1.Span.Link}
          },
          %{
            __struct__: Protox.Field,
            json_name: "droppedLinksCount",
            kind: {:scalar, 0},
            label: :optional,
            name: :dropped_links_count,
            tag: 14,
            type: :uint32
          },
          %{
            __struct__: Protox.Field,
            json_name: "status",
            kind: {:scalar, nil},
            label: :optional,
            name: :status,
            tag: 15,
            type: {:message, Opentelemetry.Proto.Trace.V1.Status}
          },
          %{
            __struct__: Protox.Field,
            json_name: "flags",
            kind: {:scalar, 0},
            label: :optional,
            name: :flags,
            tag: 16,
            type: :fixed32
          }
        ]
      end

      [
        @spec(field_def(atom) :: {:ok, Protox.Field.t()} | {:error, :no_such_field}),
        (
          def field_def(:trace_id) do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "traceId",
               kind: {:scalar, ""},
               label: :optional,
               name: :trace_id,
               tag: 1,
               type: :bytes
             }}
          end

          def field_def("traceId") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "traceId",
               kind: {:scalar, ""},
               label: :optional,
               name: :trace_id,
               tag: 1,
               type: :bytes
             }}
          end

          def field_def("trace_id") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "traceId",
               kind: {:scalar, ""},
               label: :optional,
               name: :trace_id,
               tag: 1,
               type: :bytes
             }}
          end
        ),
        (
          def field_def(:span_id) do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "spanId",
               kind: {:scalar, ""},
               label: :optional,
               name: :span_id,
               tag: 2,
               type: :bytes
             }}
          end

          def field_def("spanId") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "spanId",
               kind: {:scalar, ""},
               label: :optional,
               name: :span_id,
               tag: 2,
               type: :bytes
             }}
          end

          def field_def("span_id") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "spanId",
               kind: {:scalar, ""},
               label: :optional,
               name: :span_id,
               tag: 2,
               type: :bytes
             }}
          end
        ),
        (
          def field_def(:trace_state) do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "traceState",
               kind: {:scalar, ""},
               label: :optional,
               name: :trace_state,
               tag: 3,
               type: :string
             }}
          end

          def field_def("traceState") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "traceState",
               kind: {:scalar, ""},
               label: :optional,
               name: :trace_state,
               tag: 3,
               type: :string
             }}
          end

          def field_def("trace_state") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "traceState",
               kind: {:scalar, ""},
               label: :optional,
               name: :trace_state,
               tag: 3,
               type: :string
             }}
          end
        ),
        (
          def field_def(:parent_span_id) do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "parentSpanId",
               kind: {:scalar, ""},
               label: :optional,
               name: :parent_span_id,
               tag: 4,
               type: :bytes
             }}
          end

          def field_def("parentSpanId") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "parentSpanId",
               kind: {:scalar, ""},
               label: :optional,
               name: :parent_span_id,
               tag: 4,
               type: :bytes
             }}
          end

          def field_def("parent_span_id") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "parentSpanId",
               kind: {:scalar, ""},
               label: :optional,
               name: :parent_span_id,
               tag: 4,
               type: :bytes
             }}
          end
        ),
        (
          def field_def(:name) do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "name",
               kind: {:scalar, ""},
               label: :optional,
               name: :name,
               tag: 5,
               type: :string
             }}
          end

          def field_def("name") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "name",
               kind: {:scalar, ""},
               label: :optional,
               name: :name,
               tag: 5,
               type: :string
             }}
          end

          []
        ),
        (
          def field_def(:kind) do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "kind",
               kind: {:scalar, :SPAN_KIND_UNSPECIFIED},
               label: :optional,
               name: :kind,
               tag: 6,
               type: {:enum, Opentelemetry.Proto.Trace.V1.Span.SpanKind}
             }}
          end

          def field_def("kind") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "kind",
               kind: {:scalar, :SPAN_KIND_UNSPECIFIED},
               label: :optional,
               name: :kind,
               tag: 6,
               type: {:enum, Opentelemetry.Proto.Trace.V1.Span.SpanKind}
             }}
          end

          []
        ),
        (
          def field_def(:start_time_unix_nano) do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "startTimeUnixNano",
               kind: {:scalar, 0},
               label: :optional,
               name: :start_time_unix_nano,
               tag: 7,
               type: :fixed64
             }}
          end

          def field_def("startTimeUnixNano") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "startTimeUnixNano",
               kind: {:scalar, 0},
               label: :optional,
               name: :start_time_unix_nano,
               tag: 7,
               type: :fixed64
             }}
          end

          def field_def("start_time_unix_nano") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "startTimeUnixNano",
               kind: {:scalar, 0},
               label: :optional,
               name: :start_time_unix_nano,
               tag: 7,
               type: :fixed64
             }}
          end
        ),
        (
          def field_def(:end_time_unix_nano) do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "endTimeUnixNano",
               kind: {:scalar, 0},
               label: :optional,
               name: :end_time_unix_nano,
               tag: 8,
               type: :fixed64
             }}
          end

          def field_def("endTimeUnixNano") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "endTimeUnixNano",
               kind: {:scalar, 0},
               label: :optional,
               name: :end_time_unix_nano,
               tag: 8,
               type: :fixed64
             }}
          end

          def field_def("end_time_unix_nano") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "endTimeUnixNano",
               kind: {:scalar, 0},
               label: :optional,
               name: :end_time_unix_nano,
               tag: 8,
               type: :fixed64
             }}
          end
        ),
        (
          def field_def(:attributes) do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "attributes",
               kind: :unpacked,
               label: :repeated,
               name: :attributes,
               tag: 9,
               type: {:message, Opentelemetry.Proto.Common.V1.KeyValue}
             }}
          end

          def field_def("attributes") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "attributes",
               kind: :unpacked,
               label: :repeated,
               name: :attributes,
               tag: 9,
               type: {:message, Opentelemetry.Proto.Common.V1.KeyValue}
             }}
          end

          []
        ),
        (
          def field_def(:dropped_attributes_count) do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "droppedAttributesCount",
               kind: {:scalar, 0},
               label: :optional,
               name: :dropped_attributes_count,
               tag: 10,
               type: :uint32
             }}
          end

          def field_def("droppedAttributesCount") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "droppedAttributesCount",
               kind: {:scalar, 0},
               label: :optional,
               name: :dropped_attributes_count,
               tag: 10,
               type: :uint32
             }}
          end

          def field_def("dropped_attributes_count") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "droppedAttributesCount",
               kind: {:scalar, 0},
               label: :optional,
               name: :dropped_attributes_count,
               tag: 10,
               type: :uint32
             }}
          end
        ),
        (
          def field_def(:events) do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "events",
               kind: :unpacked,
               label: :repeated,
               name: :events,
               tag: 11,
               type: {:message, Opentelemetry.Proto.Trace.V1.Span.Event}
             }}
          end

          def field_def("events") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "events",
               kind: :unpacked,
               label: :repeated,
               name: :events,
               tag: 11,
               type: {:message, Opentelemetry.Proto.Trace.V1.Span.Event}
             }}
          end

          []
        ),
        (
          def field_def(:dropped_events_count) do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "droppedEventsCount",
               kind: {:scalar, 0},
               label: :optional,
               name: :dropped_events_count,
               tag: 12,
               type: :uint32
             }}
          end

          def field_def("droppedEventsCount") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "droppedEventsCount",
               kind: {:scalar, 0},
               label: :optional,
               name: :dropped_events_count,
               tag: 12,
               type: :uint32
             }}
          end

          def field_def("dropped_events_count") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "droppedEventsCount",
               kind: {:scalar, 0},
               label: :optional,
               name: :dropped_events_count,
               tag: 12,
               type: :uint32
             }}
          end
        ),
        (
          def field_def(:links) do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "links",
               kind: :unpacked,
               label: :repeated,
               name: :links,
               tag: 13,
               type: {:message, Opentelemetry.Proto.Trace.V1.Span.Link}
             }}
          end

          def field_def("links") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "links",
               kind: :unpacked,
               label: :repeated,
               name: :links,
               tag: 13,
               type: {:message, Opentelemetry.Proto.Trace.V1.Span.Link}
             }}
          end

          []
        ),
        (
          def field_def(:dropped_links_count) do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "droppedLinksCount",
               kind: {:scalar, 0},
               label: :optional,
               name: :dropped_links_count,
               tag: 14,
               type: :uint32
             }}
          end

          def field_def("droppedLinksCount") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "droppedLinksCount",
               kind: {:scalar, 0},
               label: :optional,
               name: :dropped_links_count,
               tag: 14,
               type: :uint32
             }}
          end

          def field_def("dropped_links_count") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "droppedLinksCount",
               kind: {:scalar, 0},
               label: :optional,
               name: :dropped_links_count,
               tag: 14,
               type: :uint32
             }}
          end
        ),
        (
          def field_def(:status) do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "status",
               kind: {:scalar, nil},
               label: :optional,
               name: :status,
               tag: 15,
               type: {:message, Opentelemetry.Proto.Trace.V1.Status}
             }}
          end

          def field_def("status") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "status",
               kind: {:scalar, nil},
               label: :optional,
               name: :status,
               tag: 15,
               type: {:message, Opentelemetry.Proto.Trace.V1.Status}
             }}
          end

          []
        ),
        (
          def field_def(:flags) do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "flags",
               kind: {:scalar, 0},
               label: :optional,
               name: :flags,
               tag: 16,
               type: :fixed32
             }}
          end

          def field_def("flags") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "flags",
               kind: {:scalar, 0},
               label: :optional,
               name: :flags,
               tag: 16,
               type: :fixed32
             }}
          end

          []
        ),
        def field_def(_) do
          {:error, :no_such_field}
        end
      ]
    )

    []

    (
      @spec required_fields() :: []
      def required_fields() do
        []
      end
    )

    (
      @spec syntax() :: atom()
      def syntax() do
        :proto3
      end
    )

    [
      @spec(default(atom) :: {:ok, boolean | integer | String.t() | float} | {:error, atom}),
      def default(:trace_id) do
        {:ok, ""}
      end,
      def default(:span_id) do
        {:ok, ""}
      end,
      def default(:trace_state) do
        {:ok, ""}
      end,
      def default(:parent_span_id) do
        {:ok, ""}
      end,
      def default(:name) do
        {:ok, ""}
      end,
      def default(:kind) do
        {:ok, :SPAN_KIND_UNSPECIFIED}
      end,
      def default(:start_time_unix_nano) do
        {:ok, 0}
      end,
      def default(:end_time_unix_nano) do
        {:ok, 0}
      end,
      def default(:attributes) do
        {:error, :no_default_value}
      end,
      def default(:dropped_attributes_count) do
        {:ok, 0}
      end,
      def default(:events) do
        {:error, :no_default_value}
      end,
      def default(:dropped_events_count) do
        {:ok, 0}
      end,
      def default(:links) do
        {:error, :no_default_value}
      end,
      def default(:dropped_links_count) do
        {:ok, 0}
      end,
      def default(:status) do
        {:ok, nil}
      end,
      def default(:flags) do
        {:ok, 0}
      end,
      def default(_) do
        {:error, :no_such_field}
      end
    ]

    (
      @spec file_options() :: struct()
      def file_options() do
        file_options = %{
          __struct__: Protox.Google.Protobuf.FileOptions,
          __uf__: [],
          cc_enable_arenas: nil,
          cc_generic_services: nil,
          csharp_namespace: "OpenTelemetry.Proto.Trace.V1",
          deprecated: nil,
          go_package: "go.opentelemetry.io/proto/otlp/trace/v1",
          java_generate_equals_and_hash: nil,
          java_generic_services: nil,
          java_multiple_files: true,
          java_outer_classname: "TraceProto",
          java_package: "io.opentelemetry.proto.trace.v1",
          java_string_check_utf8: nil,
          objc_class_prefix: nil,
          optimize_for: nil,
          php_class_prefix: nil,
          php_generic_services: nil,
          php_metadata_namespace: nil,
          php_namespace: nil,
          py_generic_services: nil,
          ruby_package: nil,
          swift_prefix: nil,
          uninterpreted_option: []
        }

        case function_exported?(Google.Protobuf.FileOptions, :decode!, 1) do
          true ->
            bytes =
              file_options
              |> Protox.Google.Protobuf.FileOptions.encode!()
              |> :binary.list_to_bin()

            apply(Google.Protobuf.FileOptions, :decode!, [bytes])

          false ->
            file_options
        end
      end
    )
  end,
  defmodule Opentelemetry.Proto.Trace.V1.Span.Event do
    @moduledoc false
    defstruct time_unix_nano: 0, name: "", attributes: [], dropped_attributes_count: 0

    (
      (
        @spec encode(struct) :: {:ok, iodata} | {:error, any}
        def encode(msg) do
          try do
            {:ok, encode!(msg)}
          rescue
            e in [Protox.EncodingError, Protox.RequiredFieldsError] -> {:error, e}
          end
        end

        @spec encode!(struct) :: iodata | no_return
        def encode!(msg) do
          []
          |> encode_time_unix_nano(msg)
          |> encode_name(msg)
          |> encode_attributes(msg)
          |> encode_dropped_attributes_count(msg)
        end
      )

      []

      [
        defp encode_time_unix_nano(acc, msg) do
          try do
            if msg.time_unix_nano == 0 do
              acc
            else
              [acc, "\t", Protox.Encode.encode_fixed64(msg.time_unix_nano)]
            end
          rescue
            ArgumentError ->
              reraise Protox.EncodingError.new(:time_unix_nano, "invalid field value"),
                      __STACKTRACE__
          end
        end,
        defp encode_name(acc, msg) do
          try do
            if msg.name == "" do
              acc
            else
              [acc, "\x12", Protox.Encode.encode_string(msg.name)]
            end
          rescue
            ArgumentError ->
              reraise Protox.EncodingError.new(:name, "invalid field value"), __STACKTRACE__
          end
        end,
        defp encode_attributes(acc, msg) do
          try do
            case msg.attributes do
              [] ->
                acc

              values ->
                [
                  acc,
                  Enum.reduce(values, [], fn value, acc ->
                    [acc, "\x1A", Protox.Encode.encode_message(value)]
                  end)
                ]
            end
          rescue
            ArgumentError ->
              reraise Protox.EncodingError.new(:attributes, "invalid field value"), __STACKTRACE__
          end
        end,
        defp encode_dropped_attributes_count(acc, msg) do
          try do
            if msg.dropped_attributes_count == 0 do
              acc
            else
              [acc, " ", Protox.Encode.encode_uint32(msg.dropped_attributes_count)]
            end
          rescue
            ArgumentError ->
              reraise Protox.EncodingError.new(:dropped_attributes_count, "invalid field value"),
                      __STACKTRACE__
          end
        end
      ]

      []
    )

    (
      (
        @spec decode(binary) :: {:ok, struct} | {:error, any}
        def decode(bytes) do
          try do
            {:ok, decode!(bytes)}
          rescue
            e in [Protox.DecodingError, Protox.IllegalTagError, Protox.RequiredFieldsError] ->
              {:error, e}
          end
        end

        (
          @spec decode!(binary) :: struct | no_return
          def decode!(bytes) do
            parse_key_value(bytes, struct(Opentelemetry.Proto.Trace.V1.Span.Event))
          end
        )
      )

      (
        @spec parse_key_value(binary, struct) :: struct
        defp parse_key_value(<<>>, msg) do
          msg
        end

        defp parse_key_value(bytes, msg) do
          {field, rest} =
            case Protox.Decode.parse_key(bytes) do
              {0, _, _} ->
                raise %Protox.IllegalTagError{}

              {1, _, bytes} ->
                {value, rest} = Protox.Decode.parse_fixed64(bytes)
                {[time_unix_nano: value], rest}

              {2, _, bytes} ->
                {len, bytes} = Protox.Varint.decode(bytes)
                {delimited, rest} = Protox.Decode.parse_delimited(bytes, len)
                {[name: delimited], rest}

              {3, _, bytes} ->
                {len, bytes} = Protox.Varint.decode(bytes)
                {delimited, rest} = Protox.Decode.parse_delimited(bytes, len)

                {[
                   attributes:
                     msg.attributes ++ [Opentelemetry.Proto.Common.V1.KeyValue.decode!(delimited)]
                 ], rest}

              {4, _, bytes} ->
                {value, rest} = Protox.Decode.parse_uint32(bytes)
                {[dropped_attributes_count: value], rest}

              {tag, wire_type, rest} ->
                {_, rest} = Protox.Decode.parse_unknown(tag, wire_type, rest)
                {[], rest}
            end

          msg_updated = struct(msg, field)
          parse_key_value(rest, msg_updated)
        end
      )

      []
    )

    (
      @spec json_decode(iodata(), keyword()) :: {:ok, struct()} | {:error, any()}
      def json_decode(input, opts \\ []) do
        try do
          {:ok, json_decode!(input, opts)}
        rescue
          e in Protox.JsonDecodingError -> {:error, e}
        end
      end

      @spec json_decode!(iodata(), keyword()) :: struct() | no_return()
      def json_decode!(input, opts \\ []) do
        {json_library_wrapper, json_library} = Protox.JsonLibrary.get_library(opts, :decode)

        Protox.JsonDecode.decode!(
          input,
          Opentelemetry.Proto.Trace.V1.Span.Event,
          &json_library_wrapper.decode!(json_library, &1)
        )
      end

      @spec json_encode(struct(), keyword()) :: {:ok, iodata()} | {:error, any()}
      def json_encode(msg, opts \\ []) do
        try do
          {:ok, json_encode!(msg, opts)}
        rescue
          e in Protox.JsonEncodingError -> {:error, e}
        end
      end

      @spec json_encode!(struct(), keyword()) :: iodata() | no_return()
      def json_encode!(msg, opts \\ []) do
        {json_library_wrapper, json_library} = Protox.JsonLibrary.get_library(opts, :encode)
        Protox.JsonEncode.encode!(msg, &json_library_wrapper.encode!(json_library, &1))
      end
    )

    []

    (
      @spec fields_defs() :: list(Protox.Field.t())
      def fields_defs() do
        [
          %{
            __struct__: Protox.Field,
            json_name: "timeUnixNano",
            kind: {:scalar, 0},
            label: :optional,
            name: :time_unix_nano,
            tag: 1,
            type: :fixed64
          },
          %{
            __struct__: Protox.Field,
            json_name: "name",
            kind: {:scalar, ""},
            label: :optional,
            name: :name,
            tag: 2,
            type: :string
          },
          %{
            __struct__: Protox.Field,
            json_name: "attributes",
            kind: :unpacked,
            label: :repeated,
            name: :attributes,
            tag: 3,
            type: {:message, Opentelemetry.Proto.Common.V1.KeyValue}
          },
          %{
            __struct__: Protox.Field,
            json_name: "droppedAttributesCount",
            kind: {:scalar, 0},
            label: :optional,
            name: :dropped_attributes_count,
            tag: 4,
            type: :uint32
          }
        ]
      end

      [
        @spec(field_def(atom) :: {:ok, Protox.Field.t()} | {:error, :no_such_field}),
        (
          def field_def(:time_unix_nano) do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "timeUnixNano",
               kind: {:scalar, 0},
               label: :optional,
               name: :time_unix_nano,
               tag: 1,
               type: :fixed64
             }}
          end

          def field_def("timeUnixNano") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "timeUnixNano",
               kind: {:scalar, 0},
               label: :optional,
               name: :time_unix_nano,
               tag: 1,
               type: :fixed64
             }}
          end

          def field_def("time_unix_nano") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "timeUnixNano",
               kind: {:scalar, 0},
               label: :optional,
               name: :time_unix_nano,
               tag: 1,
               type: :fixed64
             }}
          end
        ),
        (
          def field_def(:name) do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "name",
               kind: {:scalar, ""},
               label: :optional,
               name: :name,
               tag: 2,
               type: :string
             }}
          end

          def field_def("name") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "name",
               kind: {:scalar, ""},
               label: :optional,
               name: :name,
               tag: 2,
               type: :string
             }}
          end

          []
        ),
        (
          def field_def(:attributes) do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "attributes",
               kind: :unpacked,
               label: :repeated,
               name: :attributes,
               tag: 3,
               type: {:message, Opentelemetry.Proto.Common.V1.KeyValue}
             }}
          end

          def field_def("attributes") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "attributes",
               kind: :unpacked,
               label: :repeated,
               name: :attributes,
               tag: 3,
               type: {:message, Opentelemetry.Proto.Common.V1.KeyValue}
             }}
          end

          []
        ),
        (
          def field_def(:dropped_attributes_count) do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "droppedAttributesCount",
               kind: {:scalar, 0},
               label: :optional,
               name: :dropped_attributes_count,
               tag: 4,
               type: :uint32
             }}
          end

          def field_def("droppedAttributesCount") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "droppedAttributesCount",
               kind: {:scalar, 0},
               label: :optional,
               name: :dropped_attributes_count,
               tag: 4,
               type: :uint32
             }}
          end

          def field_def("dropped_attributes_count") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "droppedAttributesCount",
               kind: {:scalar, 0},
               label: :optional,
               name: :dropped_attributes_count,
               tag: 4,
               type: :uint32
             }}
          end
        ),
        def field_def(_) do
          {:error, :no_such_field}
        end
      ]
    )

    []

    (
      @spec required_fields() :: []
      def required_fields() do
        []
      end
    )

    (
      @spec syntax() :: atom()
      def syntax() do
        :proto3
      end
    )

    [
      @spec(default(atom) :: {:ok, boolean | integer | String.t() | float} | {:error, atom}),
      def default(:time_unix_nano) do
        {:ok, 0}
      end,
      def default(:name) do
        {:ok, ""}
      end,
      def default(:attributes) do
        {:error, :no_default_value}
      end,
      def default(:dropped_attributes_count) do
        {:ok, 0}
      end,
      def default(_) do
        {:error, :no_such_field}
      end
    ]

    (
      @spec file_options() :: struct()
      def file_options() do
        file_options = %{
          __struct__: Protox.Google.Protobuf.FileOptions,
          __uf__: [],
          cc_enable_arenas: nil,
          cc_generic_services: nil,
          csharp_namespace: "OpenTelemetry.Proto.Trace.V1",
          deprecated: nil,
          go_package: "go.opentelemetry.io/proto/otlp/trace/v1",
          java_generate_equals_and_hash: nil,
          java_generic_services: nil,
          java_multiple_files: true,
          java_outer_classname: "TraceProto",
          java_package: "io.opentelemetry.proto.trace.v1",
          java_string_check_utf8: nil,
          objc_class_prefix: nil,
          optimize_for: nil,
          php_class_prefix: nil,
          php_generic_services: nil,
          php_metadata_namespace: nil,
          php_namespace: nil,
          py_generic_services: nil,
          ruby_package: nil,
          swift_prefix: nil,
          uninterpreted_option: []
        }

        case function_exported?(Google.Protobuf.FileOptions, :decode!, 1) do
          true ->
            bytes =
              file_options
              |> Protox.Google.Protobuf.FileOptions.encode!()
              |> :binary.list_to_bin()

            apply(Google.Protobuf.FileOptions, :decode!, [bytes])

          false ->
            file_options
        end
      end
    )
  end,
  defmodule Opentelemetry.Proto.Trace.V1.Span.Link do
    @moduledoc false
    defstruct trace_id: "",
              span_id: "",
              trace_state: "",
              attributes: [],
              dropped_attributes_count: 0,
              flags: 0

    (
      (
        @spec encode(struct) :: {:ok, iodata} | {:error, any}
        def encode(msg) do
          try do
            {:ok, encode!(msg)}
          rescue
            e in [Protox.EncodingError, Protox.RequiredFieldsError] -> {:error, e}
          end
        end

        @spec encode!(struct) :: iodata | no_return
        def encode!(msg) do
          []
          |> encode_trace_id(msg)
          |> encode_span_id(msg)
          |> encode_trace_state(msg)
          |> encode_attributes(msg)
          |> encode_dropped_attributes_count(msg)
          |> encode_flags(msg)
        end
      )

      []

      [
        defp encode_trace_id(acc, msg) do
          try do
            if msg.trace_id == "" do
              acc
            else
              [acc, "\n", Protox.Encode.encode_bytes(msg.trace_id)]
            end
          rescue
            ArgumentError ->
              reraise Protox.EncodingError.new(:trace_id, "invalid field value"), __STACKTRACE__
          end
        end,
        defp encode_span_id(acc, msg) do
          try do
            if msg.span_id == "" do
              acc
            else
              [acc, "\x12", Protox.Encode.encode_bytes(msg.span_id)]
            end
          rescue
            ArgumentError ->
              reraise Protox.EncodingError.new(:span_id, "invalid field value"), __STACKTRACE__
          end
        end,
        defp encode_trace_state(acc, msg) do
          try do
            if msg.trace_state == "" do
              acc
            else
              [acc, "\x1A", Protox.Encode.encode_string(msg.trace_state)]
            end
          rescue
            ArgumentError ->
              reraise Protox.EncodingError.new(:trace_state, "invalid field value"),
                      __STACKTRACE__
          end
        end,
        defp encode_attributes(acc, msg) do
          try do
            case msg.attributes do
              [] ->
                acc

              values ->
                [
                  acc,
                  Enum.reduce(values, [], fn value, acc ->
                    [acc, "\"", Protox.Encode.encode_message(value)]
                  end)
                ]
            end
          rescue
            ArgumentError ->
              reraise Protox.EncodingError.new(:attributes, "invalid field value"), __STACKTRACE__
          end
        end,
        defp encode_dropped_attributes_count(acc, msg) do
          try do
            if msg.dropped_attributes_count == 0 do
              acc
            else
              [acc, "(", Protox.Encode.encode_uint32(msg.dropped_attributes_count)]
            end
          rescue
            ArgumentError ->
              reraise Protox.EncodingError.new(:dropped_attributes_count, "invalid field value"),
                      __STACKTRACE__
          end
        end,
        defp encode_flags(acc, msg) do
          try do
            if msg.flags == 0 do
              acc
            else
              [acc, "5", Protox.Encode.encode_fixed32(msg.flags)]
            end
          rescue
            ArgumentError ->
              reraise Protox.EncodingError.new(:flags, "invalid field value"), __STACKTRACE__
          end
        end
      ]

      []
    )

    (
      (
        @spec decode(binary) :: {:ok, struct} | {:error, any}
        def decode(bytes) do
          try do
            {:ok, decode!(bytes)}
          rescue
            e in [Protox.DecodingError, Protox.IllegalTagError, Protox.RequiredFieldsError] ->
              {:error, e}
          end
        end

        (
          @spec decode!(binary) :: struct | no_return
          def decode!(bytes) do
            parse_key_value(bytes, struct(Opentelemetry.Proto.Trace.V1.Span.Link))
          end
        )
      )

      (
        @spec parse_key_value(binary, struct) :: struct
        defp parse_key_value(<<>>, msg) do
          msg
        end

        defp parse_key_value(bytes, msg) do
          {field, rest} =
            case Protox.Decode.parse_key(bytes) do
              {0, _, _} ->
                raise %Protox.IllegalTagError{}

              {1, _, bytes} ->
                {len, bytes} = Protox.Varint.decode(bytes)
                {delimited, rest} = Protox.Decode.parse_delimited(bytes, len)
                {[trace_id: delimited], rest}

              {2, _, bytes} ->
                {len, bytes} = Protox.Varint.decode(bytes)
                {delimited, rest} = Protox.Decode.parse_delimited(bytes, len)
                {[span_id: delimited], rest}

              {3, _, bytes} ->
                {len, bytes} = Protox.Varint.decode(bytes)
                {delimited, rest} = Protox.Decode.parse_delimited(bytes, len)
                {[trace_state: delimited], rest}

              {4, _, bytes} ->
                {len, bytes} = Protox.Varint.decode(bytes)
                {delimited, rest} = Protox.Decode.parse_delimited(bytes, len)

                {[
                   attributes:
                     msg.attributes ++ [Opentelemetry.Proto.Common.V1.KeyValue.decode!(delimited)]
                 ], rest}

              {5, _, bytes} ->
                {value, rest} = Protox.Decode.parse_uint32(bytes)
                {[dropped_attributes_count: value], rest}

              {6, _, bytes} ->
                {value, rest} = Protox.Decode.parse_fixed32(bytes)
                {[flags: value], rest}

              {tag, wire_type, rest} ->
                {_, rest} = Protox.Decode.parse_unknown(tag, wire_type, rest)
                {[], rest}
            end

          msg_updated = struct(msg, field)
          parse_key_value(rest, msg_updated)
        end
      )

      []
    )

    (
      @spec json_decode(iodata(), keyword()) :: {:ok, struct()} | {:error, any()}
      def json_decode(input, opts \\ []) do
        try do
          {:ok, json_decode!(input, opts)}
        rescue
          e in Protox.JsonDecodingError -> {:error, e}
        end
      end

      @spec json_decode!(iodata(), keyword()) :: struct() | no_return()
      def json_decode!(input, opts \\ []) do
        {json_library_wrapper, json_library} = Protox.JsonLibrary.get_library(opts, :decode)

        Protox.JsonDecode.decode!(
          input,
          Opentelemetry.Proto.Trace.V1.Span.Link,
          &json_library_wrapper.decode!(json_library, &1)
        )
      end

      @spec json_encode(struct(), keyword()) :: {:ok, iodata()} | {:error, any()}
      def json_encode(msg, opts \\ []) do
        try do
          {:ok, json_encode!(msg, opts)}
        rescue
          e in Protox.JsonEncodingError -> {:error, e}
        end
      end

      @spec json_encode!(struct(), keyword()) :: iodata() | no_return()
      def json_encode!(msg, opts \\ []) do
        {json_library_wrapper, json_library} = Protox.JsonLibrary.get_library(opts, :encode)
        Protox.JsonEncode.encode!(msg, &json_library_wrapper.encode!(json_library, &1))
      end
    )

    []

    (
      @spec fields_defs() :: list(Protox.Field.t())
      def fields_defs() do
        [
          %{
            __struct__: Protox.Field,
            json_name: "traceId",
            kind: {:scalar, ""},
            label: :optional,
            name: :trace_id,
            tag: 1,
            type: :bytes
          },
          %{
            __struct__: Protox.Field,
            json_name: "spanId",
            kind: {:scalar, ""},
            label: :optional,
            name: :span_id,
            tag: 2,
            type: :bytes
          },
          %{
            __struct__: Protox.Field,
            json_name: "traceState",
            kind: {:scalar, ""},
            label: :optional,
            name: :trace_state,
            tag: 3,
            type: :string
          },
          %{
            __struct__: Protox.Field,
            json_name: "attributes",
            kind: :unpacked,
            label: :repeated,
            name: :attributes,
            tag: 4,
            type: {:message, Opentelemetry.Proto.Common.V1.KeyValue}
          },
          %{
            __struct__: Protox.Field,
            json_name: "droppedAttributesCount",
            kind: {:scalar, 0},
            label: :optional,
            name: :dropped_attributes_count,
            tag: 5,
            type: :uint32
          },
          %{
            __struct__: Protox.Field,
            json_name: "flags",
            kind: {:scalar, 0},
            label: :optional,
            name: :flags,
            tag: 6,
            type: :fixed32
          }
        ]
      end

      [
        @spec(field_def(atom) :: {:ok, Protox.Field.t()} | {:error, :no_such_field}),
        (
          def field_def(:trace_id) do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "traceId",
               kind: {:scalar, ""},
               label: :optional,
               name: :trace_id,
               tag: 1,
               type: :bytes
             }}
          end

          def field_def("traceId") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "traceId",
               kind: {:scalar, ""},
               label: :optional,
               name: :trace_id,
               tag: 1,
               type: :bytes
             }}
          end

          def field_def("trace_id") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "traceId",
               kind: {:scalar, ""},
               label: :optional,
               name: :trace_id,
               tag: 1,
               type: :bytes
             }}
          end
        ),
        (
          def field_def(:span_id) do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "spanId",
               kind: {:scalar, ""},
               label: :optional,
               name: :span_id,
               tag: 2,
               type: :bytes
             }}
          end

          def field_def("spanId") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "spanId",
               kind: {:scalar, ""},
               label: :optional,
               name: :span_id,
               tag: 2,
               type: :bytes
             }}
          end

          def field_def("span_id") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "spanId",
               kind: {:scalar, ""},
               label: :optional,
               name: :span_id,
               tag: 2,
               type: :bytes
             }}
          end
        ),
        (
          def field_def(:trace_state) do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "traceState",
               kind: {:scalar, ""},
               label: :optional,
               name: :trace_state,
               tag: 3,
               type: :string
             }}
          end

          def field_def("traceState") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "traceState",
               kind: {:scalar, ""},
               label: :optional,
               name: :trace_state,
               tag: 3,
               type: :string
             }}
          end

          def field_def("trace_state") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "traceState",
               kind: {:scalar, ""},
               label: :optional,
               name: :trace_state,
               tag: 3,
               type: :string
             }}
          end
        ),
        (
          def field_def(:attributes) do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "attributes",
               kind: :unpacked,
               label: :repeated,
               name: :attributes,
               tag: 4,
               type: {:message, Opentelemetry.Proto.Common.V1.KeyValue}
             }}
          end

          def field_def("attributes") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "attributes",
               kind: :unpacked,
               label: :repeated,
               name: :attributes,
               tag: 4,
               type: {:message, Opentelemetry.Proto.Common.V1.KeyValue}
             }}
          end

          []
        ),
        (
          def field_def(:dropped_attributes_count) do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "droppedAttributesCount",
               kind: {:scalar, 0},
               label: :optional,
               name: :dropped_attributes_count,
               tag: 5,
               type: :uint32
             }}
          end

          def field_def("droppedAttributesCount") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "droppedAttributesCount",
               kind: {:scalar, 0},
               label: :optional,
               name: :dropped_attributes_count,
               tag: 5,
               type: :uint32
             }}
          end

          def field_def("dropped_attributes_count") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "droppedAttributesCount",
               kind: {:scalar, 0},
               label: :optional,
               name: :dropped_attributes_count,
               tag: 5,
               type: :uint32
             }}
          end
        ),
        (
          def field_def(:flags) do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "flags",
               kind: {:scalar, 0},
               label: :optional,
               name: :flags,
               tag: 6,
               type: :fixed32
             }}
          end

          def field_def("flags") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "flags",
               kind: {:scalar, 0},
               label: :optional,
               name: :flags,
               tag: 6,
               type: :fixed32
             }}
          end

          []
        ),
        def field_def(_) do
          {:error, :no_such_field}
        end
      ]
    )

    []

    (
      @spec required_fields() :: []
      def required_fields() do
        []
      end
    )

    (
      @spec syntax() :: atom()
      def syntax() do
        :proto3
      end
    )

    [
      @spec(default(atom) :: {:ok, boolean | integer | String.t() | float} | {:error, atom}),
      def default(:trace_id) do
        {:ok, ""}
      end,
      def default(:span_id) do
        {:ok, ""}
      end,
      def default(:trace_state) do
        {:ok, ""}
      end,
      def default(:attributes) do
        {:error, :no_default_value}
      end,
      def default(:dropped_attributes_count) do
        {:ok, 0}
      end,
      def default(:flags) do
        {:ok, 0}
      end,
      def default(_) do
        {:error, :no_such_field}
      end
    ]

    (
      @spec file_options() :: struct()
      def file_options() do
        file_options = %{
          __struct__: Protox.Google.Protobuf.FileOptions,
          __uf__: [],
          cc_enable_arenas: nil,
          cc_generic_services: nil,
          csharp_namespace: "OpenTelemetry.Proto.Trace.V1",
          deprecated: nil,
          go_package: "go.opentelemetry.io/proto/otlp/trace/v1",
          java_generate_equals_and_hash: nil,
          java_generic_services: nil,
          java_multiple_files: true,
          java_outer_classname: "TraceProto",
          java_package: "io.opentelemetry.proto.trace.v1",
          java_string_check_utf8: nil,
          objc_class_prefix: nil,
          optimize_for: nil,
          php_class_prefix: nil,
          php_generic_services: nil,
          php_metadata_namespace: nil,
          php_namespace: nil,
          py_generic_services: nil,
          ruby_package: nil,
          swift_prefix: nil,
          uninterpreted_option: []
        }

        case function_exported?(Google.Protobuf.FileOptions, :decode!, 1) do
          true ->
            bytes =
              file_options
              |> Protox.Google.Protobuf.FileOptions.encode!()
              |> :binary.list_to_bin()

            apply(Google.Protobuf.FileOptions, :decode!, [bytes])

          false ->
            file_options
        end
      end
    )
  end,
  defmodule Opentelemetry.Proto.Trace.V1.Status do
    @moduledoc false
    defstruct message: "", code: :STATUS_CODE_UNSET

    (
      (
        @spec encode(struct) :: {:ok, iodata} | {:error, any}
        def encode(msg) do
          try do
            {:ok, encode!(msg)}
          rescue
            e in [Protox.EncodingError, Protox.RequiredFieldsError] -> {:error, e}
          end
        end

        @spec encode!(struct) :: iodata | no_return
        def encode!(msg) do
          [] |> encode_message(msg) |> encode_code(msg)
        end
      )

      []

      [
        defp encode_message(acc, msg) do
          try do
            if msg.message == "" do
              acc
            else
              [acc, "\x12", Protox.Encode.encode_string(msg.message)]
            end
          rescue
            ArgumentError ->
              reraise Protox.EncodingError.new(:message, "invalid field value"), __STACKTRACE__
          end
        end,
        defp encode_code(acc, msg) do
          try do
            if msg.code == :STATUS_CODE_UNSET do
              acc
            else
              [
                acc,
                "\x18",
                msg.code
                |> Opentelemetry.Proto.Trace.V1.Status.StatusCode.encode()
                |> Protox.Encode.encode_enum()
              ]
            end
          rescue
            ArgumentError ->
              reraise Protox.EncodingError.new(:code, "invalid field value"), __STACKTRACE__
          end
        end
      ]

      []
    )

    (
      (
        @spec decode(binary) :: {:ok, struct} | {:error, any}
        def decode(bytes) do
          try do
            {:ok, decode!(bytes)}
          rescue
            e in [Protox.DecodingError, Protox.IllegalTagError, Protox.RequiredFieldsError] ->
              {:error, e}
          end
        end

        (
          @spec decode!(binary) :: struct | no_return
          def decode!(bytes) do
            parse_key_value(bytes, struct(Opentelemetry.Proto.Trace.V1.Status))
          end
        )
      )

      (
        @spec parse_key_value(binary, struct) :: struct
        defp parse_key_value(<<>>, msg) do
          msg
        end

        defp parse_key_value(bytes, msg) do
          {field, rest} =
            case Protox.Decode.parse_key(bytes) do
              {0, _, _} ->
                raise %Protox.IllegalTagError{}

              {2, _, bytes} ->
                {len, bytes} = Protox.Varint.decode(bytes)
                {delimited, rest} = Protox.Decode.parse_delimited(bytes, len)
                {[message: delimited], rest}

              {3, _, bytes} ->
                {value, rest} =
                  Protox.Decode.parse_enum(bytes, Opentelemetry.Proto.Trace.V1.Status.StatusCode)

                {[code: value], rest}

              {tag, wire_type, rest} ->
                {_, rest} = Protox.Decode.parse_unknown(tag, wire_type, rest)
                {[], rest}
            end

          msg_updated = struct(msg, field)
          parse_key_value(rest, msg_updated)
        end
      )

      []
    )

    (
      @spec json_decode(iodata(), keyword()) :: {:ok, struct()} | {:error, any()}
      def json_decode(input, opts \\ []) do
        try do
          {:ok, json_decode!(input, opts)}
        rescue
          e in Protox.JsonDecodingError -> {:error, e}
        end
      end

      @spec json_decode!(iodata(), keyword()) :: struct() | no_return()
      def json_decode!(input, opts \\ []) do
        {json_library_wrapper, json_library} = Protox.JsonLibrary.get_library(opts, :decode)

        Protox.JsonDecode.decode!(
          input,
          Opentelemetry.Proto.Trace.V1.Status,
          &json_library_wrapper.decode!(json_library, &1)
        )
      end

      @spec json_encode(struct(), keyword()) :: {:ok, iodata()} | {:error, any()}
      def json_encode(msg, opts \\ []) do
        try do
          {:ok, json_encode!(msg, opts)}
        rescue
          e in Protox.JsonEncodingError -> {:error, e}
        end
      end

      @spec json_encode!(struct(), keyword()) :: iodata() | no_return()
      def json_encode!(msg, opts \\ []) do
        {json_library_wrapper, json_library} = Protox.JsonLibrary.get_library(opts, :encode)
        Protox.JsonEncode.encode!(msg, &json_library_wrapper.encode!(json_library, &1))
      end
    )

    []

    (
      @spec fields_defs() :: list(Protox.Field.t())
      def fields_defs() do
        [
          %{
            __struct__: Protox.Field,
            json_name: "message",
            kind: {:scalar, ""},
            label: :optional,
            name: :message,
            tag: 2,
            type: :string
          },
          %{
            __struct__: Protox.Field,
            json_name: "code",
            kind: {:scalar, :STATUS_CODE_UNSET},
            label: :optional,
            name: :code,
            tag: 3,
            type: {:enum, Opentelemetry.Proto.Trace.V1.Status.StatusCode}
          }
        ]
      end

      [
        @spec(field_def(atom) :: {:ok, Protox.Field.t()} | {:error, :no_such_field}),
        (
          def field_def(:message) do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "message",
               kind: {:scalar, ""},
               label: :optional,
               name: :message,
               tag: 2,
               type: :string
             }}
          end

          def field_def("message") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "message",
               kind: {:scalar, ""},
               label: :optional,
               name: :message,
               tag: 2,
               type: :string
             }}
          end

          []
        ),
        (
          def field_def(:code) do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "code",
               kind: {:scalar, :STATUS_CODE_UNSET},
               label: :optional,
               name: :code,
               tag: 3,
               type: {:enum, Opentelemetry.Proto.Trace.V1.Status.StatusCode}
             }}
          end

          def field_def("code") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "code",
               kind: {:scalar, :STATUS_CODE_UNSET},
               label: :optional,
               name: :code,
               tag: 3,
               type: {:enum, Opentelemetry.Proto.Trace.V1.Status.StatusCode}
             }}
          end

          []
        ),
        def field_def(_) do
          {:error, :no_such_field}
        end
      ]
    )

    []

    (
      @spec required_fields() :: []
      def required_fields() do
        []
      end
    )

    (
      @spec syntax() :: atom()
      def syntax() do
        :proto3
      end
    )

    [
      @spec(default(atom) :: {:ok, boolean | integer | String.t() | float} | {:error, atom}),
      def default(:message) do
        {:ok, ""}
      end,
      def default(:code) do
        {:ok, :STATUS_CODE_UNSET}
      end,
      def default(_) do
        {:error, :no_such_field}
      end
    ]

    (
      @spec file_options() :: struct()
      def file_options() do
        file_options = %{
          __struct__: Protox.Google.Protobuf.FileOptions,
          __uf__: [],
          cc_enable_arenas: nil,
          cc_generic_services: nil,
          csharp_namespace: "OpenTelemetry.Proto.Trace.V1",
          deprecated: nil,
          go_package: "go.opentelemetry.io/proto/otlp/trace/v1",
          java_generate_equals_and_hash: nil,
          java_generic_services: nil,
          java_multiple_files: true,
          java_outer_classname: "TraceProto",
          java_package: "io.opentelemetry.proto.trace.v1",
          java_string_check_utf8: nil,
          objc_class_prefix: nil,
          optimize_for: nil,
          php_class_prefix: nil,
          php_generic_services: nil,
          php_metadata_namespace: nil,
          php_namespace: nil,
          py_generic_services: nil,
          ruby_package: nil,
          swift_prefix: nil,
          uninterpreted_option: []
        }

        case function_exported?(Google.Protobuf.FileOptions, :decode!, 1) do
          true ->
            bytes =
              file_options
              |> Protox.Google.Protobuf.FileOptions.encode!()
              |> :binary.list_to_bin()

            apply(Google.Protobuf.FileOptions, :decode!, [bytes])

          false ->
            file_options
        end
      end
    )
  end,
  defmodule Opentelemetry.Proto.Trace.V1.TracesData do
    @moduledoc false
    defstruct resource_spans: []

    (
      (
        @spec encode(struct) :: {:ok, iodata} | {:error, any}
        def encode(msg) do
          try do
            {:ok, encode!(msg)}
          rescue
            e in [Protox.EncodingError, Protox.RequiredFieldsError] -> {:error, e}
          end
        end

        @spec encode!(struct) :: iodata | no_return
        def encode!(msg) do
          [] |> encode_resource_spans(msg)
        end
      )

      []

      [
        defp encode_resource_spans(acc, msg) do
          try do
            case msg.resource_spans do
              [] ->
                acc

              values ->
                [
                  acc,
                  Enum.reduce(values, [], fn value, acc ->
                    [acc, "\n", Protox.Encode.encode_message(value)]
                  end)
                ]
            end
          rescue
            ArgumentError ->
              reraise Protox.EncodingError.new(:resource_spans, "invalid field value"),
                      __STACKTRACE__
          end
        end
      ]

      []
    )

    (
      (
        @spec decode(binary) :: {:ok, struct} | {:error, any}
        def decode(bytes) do
          try do
            {:ok, decode!(bytes)}
          rescue
            e in [Protox.DecodingError, Protox.IllegalTagError, Protox.RequiredFieldsError] ->
              {:error, e}
          end
        end

        (
          @spec decode!(binary) :: struct | no_return
          def decode!(bytes) do
            parse_key_value(bytes, struct(Opentelemetry.Proto.Trace.V1.TracesData))
          end
        )
      )

      (
        @spec parse_key_value(binary, struct) :: struct
        defp parse_key_value(<<>>, msg) do
          msg
        end

        defp parse_key_value(bytes, msg) do
          {field, rest} =
            case Protox.Decode.parse_key(bytes) do
              {0, _, _} ->
                raise %Protox.IllegalTagError{}

              {1, _, bytes} ->
                {len, bytes} = Protox.Varint.decode(bytes)
                {delimited, rest} = Protox.Decode.parse_delimited(bytes, len)

                {[
                   resource_spans:
                     msg.resource_spans ++
                       [Opentelemetry.Proto.Trace.V1.ResourceSpans.decode!(delimited)]
                 ], rest}

              {tag, wire_type, rest} ->
                {_, rest} = Protox.Decode.parse_unknown(tag, wire_type, rest)
                {[], rest}
            end

          msg_updated = struct(msg, field)
          parse_key_value(rest, msg_updated)
        end
      )

      []
    )

    (
      @spec json_decode(iodata(), keyword()) :: {:ok, struct()} | {:error, any()}
      def json_decode(input, opts \\ []) do
        try do
          {:ok, json_decode!(input, opts)}
        rescue
          e in Protox.JsonDecodingError -> {:error, e}
        end
      end

      @spec json_decode!(iodata(), keyword()) :: struct() | no_return()
      def json_decode!(input, opts \\ []) do
        {json_library_wrapper, json_library} = Protox.JsonLibrary.get_library(opts, :decode)

        Protox.JsonDecode.decode!(
          input,
          Opentelemetry.Proto.Trace.V1.TracesData,
          &json_library_wrapper.decode!(json_library, &1)
        )
      end

      @spec json_encode(struct(), keyword()) :: {:ok, iodata()} | {:error, any()}
      def json_encode(msg, opts \\ []) do
        try do
          {:ok, json_encode!(msg, opts)}
        rescue
          e in Protox.JsonEncodingError -> {:error, e}
        end
      end

      @spec json_encode!(struct(), keyword()) :: iodata() | no_return()
      def json_encode!(msg, opts \\ []) do
        {json_library_wrapper, json_library} = Protox.JsonLibrary.get_library(opts, :encode)
        Protox.JsonEncode.encode!(msg, &json_library_wrapper.encode!(json_library, &1))
      end
    )

    []

    (
      @spec fields_defs() :: list(Protox.Field.t())
      def fields_defs() do
        [
          %{
            __struct__: Protox.Field,
            json_name: "resourceSpans",
            kind: :unpacked,
            label: :repeated,
            name: :resource_spans,
            tag: 1,
            type: {:message, Opentelemetry.Proto.Trace.V1.ResourceSpans}
          }
        ]
      end

      [
        @spec(field_def(atom) :: {:ok, Protox.Field.t()} | {:error, :no_such_field}),
        (
          def field_def(:resource_spans) do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "resourceSpans",
               kind: :unpacked,
               label: :repeated,
               name: :resource_spans,
               tag: 1,
               type: {:message, Opentelemetry.Proto.Trace.V1.ResourceSpans}
             }}
          end

          def field_def("resourceSpans") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "resourceSpans",
               kind: :unpacked,
               label: :repeated,
               name: :resource_spans,
               tag: 1,
               type: {:message, Opentelemetry.Proto.Trace.V1.ResourceSpans}
             }}
          end

          def field_def("resource_spans") do
            {:ok,
             %{
               __struct__: Protox.Field,
               json_name: "resourceSpans",
               kind: :unpacked,
               label: :repeated,
               name: :resource_spans,
               tag: 1,
               type: {:message, Opentelemetry.Proto.Trace.V1.ResourceSpans}
             }}
          end
        ),
        def field_def(_) do
          {:error, :no_such_field}
        end
      ]
    )

    []

    (
      @spec required_fields() :: []
      def required_fields() do
        []
      end
    )

    (
      @spec syntax() :: atom()
      def syntax() do
        :proto3
      end
    )

    [
      @spec(default(atom) :: {:ok, boolean | integer | String.t() | float} | {:error, atom}),
      def default(:resource_spans) do
        {:error, :no_default_value}
      end,
      def default(_) do
        {:error, :no_such_field}
      end
    ]

    (
      @spec file_options() :: struct()
      def file_options() do
        file_options = %{
          __struct__: Protox.Google.Protobuf.FileOptions,
          __uf__: [],
          cc_enable_arenas: nil,
          cc_generic_services: nil,
          csharp_namespace: "OpenTelemetry.Proto.Trace.V1",
          deprecated: nil,
          go_package: "go.opentelemetry.io/proto/otlp/trace/v1",
          java_generate_equals_and_hash: nil,
          java_generic_services: nil,
          java_multiple_files: true,
          java_outer_classname: "TraceProto",
          java_package: "io.opentelemetry.proto.trace.v1",
          java_string_check_utf8: nil,
          objc_class_prefix: nil,
          optimize_for: nil,
          php_class_prefix: nil,
          php_generic_services: nil,
          php_metadata_namespace: nil,
          php_namespace: nil,
          py_generic_services: nil,
          ruby_package: nil,
          swift_prefix: nil,
          uninterpreted_option: []
        }

        case function_exported?(Google.Protobuf.FileOptions, :decode!, 1) do
          true ->
            bytes =
              file_options
              |> Protox.Google.Protobuf.FileOptions.encode!()
              |> :binary.list_to_bin()

            apply(Google.Protobuf.FileOptions, :decode!, [bytes])

          false ->
            file_options
        end
      end
    )
  end
]
