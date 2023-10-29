defmodule LatchWeb.TraceLive do
  # See https://github.com/DockYard/flame_on for the inspiration for the SVG

  use Phoenix.LiveComponent

  alias Latch.TraceKeeper

  @datetime_precision :millisecond
  def render(assigns) do
    assigns =
      assigns
      |> assign(
        :scaling_factor,
        assigns.diagram_width /
          max(
            DateTime.diff(
              assigns.latest_timestamp,
              assigns.earliest_timestamp,
              @datetime_precision
            ),
            1
          )
      )

    ~H"""
    <div>
      <h2>Trace view - <%= hd(hd(@spans)).service_name %></h2>
      <svg
        width={@diagram_width}
        height={length(@spans) * @block_height}
        style="background-color: white;"
        class="svg_trace"
        phx-target={@myself}
      >
        <style>
            svg.svg_trace {
              box-sizing: content-box;
              padding: 5px;
              background-color: #DFDBE5;
          background-image: url("data:image/svg+xml,%3Csvg width='6' height='6' viewBox='0 0 6 6' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='%239C92AC' fill-opacity='0.13' fill-rule='evenodd'%3E%3Cpath d='M5 0h1L0 6V5zM6 5v1H5z'/%3E%3C/g%3E%3C/svg%3E");
          margin-bottom: 25px;
              }
              svg > svg {
                cursor: pointer;
              }

              svg > svg > rect {
                stroke: white;
                rx: 5px;
              }

              svg > svg > text {
                font-size: <%= @block_height / 2 %>px;
                font-family: monospace;
                dominant-baseline: middle;
              }
        </style>
        <%= for {blocks, row} <- Enum.with_index(@spans) do %>
          <%= for block <- blocks do %>
            <%= render_span(%{
              block: block,
              block_height: @block_height,
              socket: @socket,
              myself: @myself,
              scaled_start:
                DateTime.diff(block.start_time, @earliest_timestamp, @datetime_precision) *
                  @scaling_factor,
              scaled_end:
                DateTime.diff(block.end_time, @earliest_timestamp, @datetime_precision) *
                  @scaling_factor,
              level: row
            }) %>
          <% end %>
        <% end %>
      </svg>
      <pre style="border: 1px solid green; padding: 15px;">
    <%= inspect(Enum.find(List.flatten(@spans), fn x -> x.span_id == @selected_span end), pretty: true) %>
      </pre>
    </div>
    """
  end

  defp render_span(assigns) do
    ~H"""
    <svg
      width={max(trunc(@scaled_end - @scaled_start), 50)}
      height={@block_height}
      x={trunc(@scaled_start)}
      y={@level * @block_height}
      phx-click="select_span"
      phx-value-span-id={@block.span_id}
      phx-target={@myself}
    >
      <rect width="100%" height="100%" style={"fill: #{color_for_module(@block.scope_name)};"}></rect>
      <text x={@block_height / 4} y={@block_height * 0.5}>
        <%= @block.name %>
      </text>
      <title>
        <%= @block.name %>
      </title>
    </svg>
    """
  end

  def update(assigns, socket) do
    spans = TraceKeeper.get_records(assigns.trace_id)

    {earliest, latest} =
      Enum.reduce(spans, {nil, nil}, fn map, {earliest, latest} ->
        earliest =
          case earliest do
            nil -> map.start_time
            timestamp -> Enum.min([timestamp, map.start_time], DateTime)
          end

        latest =
          case latest do
            nil -> map.end_time
            timestamp -> Enum.max([timestamp, map.end_time], DateTime)
          end

        {earliest, latest}
      end)

    spans =
      spans
      |> Latch.TraceProcessor.order_structs_by_bfs()
      |> multilevel()

    socket =
      socket
      |> assign(:earliest_timestamp, earliest)
      |> assign(:latest_timestamp, latest)
      |> assign(:selected_span, hd(hd(spans)).span_id)
      |> assign(:datetime_precision, @datetime_precision)
      |> assign(:diagram_width, 800)
      |> assign(:block_height, 25)
      |> assign(:spans, spans)

    {:ok, socket}
  end

  defp color_for_module(module) do
    red = :erlang.phash2(module <> "red", 180) |> Kernel.+(75) |> Integer.to_string(16)
    green = :erlang.phash2(module <> "green", 180) |> Kernel.+(75) |> Integer.to_string(16)
    blue = :erlang.phash2(module <> "blue", 180) |> Kernel.+(75) |> Integer.to_string(16)

    "\##{pad(red)}#{pad(green)}#{pad(blue)}"
  end

  defp pad(str) do
    if String.length(str) == 1 do
      "0" <> str
    else
      str
    end
  end

  def multilevel(spans) do
    chunk_fun = fn
      element, [] ->
        {:cont, [element]}

      element, acc ->
        last = hd(acc)

        unless DateTime.compare(element.start_time, last.end_time) == :gt do
          {:cont, Enum.reverse(acc), [element]}
        else
          {:cont, [element | acc]}
        end
    end

    after_fun = fn
      [] -> {:cont, []}
      acc -> {:cont, Enum.reverse(acc), []}
    end

    spans
    |> Enum.flat_map(fn spans_level ->
      Enum.chunk_while(spans_level, [], chunk_fun, after_fun)
    end)
  end

  def handle_event("select_span", %{"span-id" => value}, socket) do
    socket =
      socket
      |> assign(:selected_span, value)

    {:noreply, socket}
  end
end
