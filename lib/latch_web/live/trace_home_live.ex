defmodule LatchWeb.TraceHomeLive do
  use LatchWeb, :live_view

  alias Latch.TraceKeeper

  @impl true
  def render(assigns) do
    ~H"""
    <.modal id="details-modal">
      <%= if @selected_trace do %>
        <.live_component module={LatchWeb.TraceLive} id="traceview" trace_id={@selected_trace} />
      <% else %>
        No trace selected
      <% end %>
    </.modal>
    <h1 class="mb-4 text-4xl font-extrabold leading-none tracking-tight text-gray-900 md:text-3xl lg:text-4xl dark:text-white">
      Trace List
    </h1>
    <table class="w-full text-sm text-left text-gray-500 dark:text-gray-400">
      <thead class="text-xs text-gray-700 uppercase bg-gray-50 dark:bg-gray-700 dark:text-gray-400">
        <tr>
          <th scope="col" class="px-6 py-3">
            Date
          </th>
          <th scope="col" class="px-6 py-3">
            Service
          </th>
          <th scope="col" class="px-6 py-3">
            Resource
          </th>
          <th scope="col" class="px-6 py-3">
            Duration
          </th>
        </tr>
      </thead>
      <tbody id="traces" phx-update="stream">
        <tr
          :for={{dom_id, trace} <- @streams.traces}
          class="bg-white border-b dark:bg-gray-800 dark:border-gray-700"
          id={dom_id}
          phx-click={
            show_modal("details-modal") |> JS.push("select_trace", value: %{id: trace.trace_id})
          }
          style="cursor: pointer"
        >
          <td class="px-6 py-4">
            <%= trace.start_time |> DateTime.truncate(:second) %>
          </td>
          <td class="px-6 py-4">
            <%= trace.service_name %>
          </td>
          <td class="px-6 py-4">
            <%= trace.name %>
          </td>
          <td class="px-6 py-4">
            <%= format_time_diff(trace.end_time, trace.start_time) %>
          </td>
        </tr>
      </tbody>
    </table>
    """
  end

  def trace_table(assigns) do
    ~H"""
    <table class="w-full text-sm text-left text-gray-500 dark:text-gray-400">
      <thead class="text-xs text-gray-700 uppercase bg-gray-50 dark:bg-gray-700 dark:text-gray-400">
        <tr>
          <th scope="col" class="px-6 py-3">
            Date
          </th>
          <th scope="col" class="px-6 py-3">
            Service
          </th>
          <th scope="col" class="px-6 py-3">
            Resource
          </th>
          <th scope="col" class="px-6 py-3">
            Duration
          </th>
        </tr>
      </thead>
      <tbody id="traces" phx-update="stream">
        <tr
          :for={{dom_id, trace} <- @streams.traces}
          class="bg-white border-b dark:bg-gray-800 dark:border-gray-700"
          id={dom_id}
        >
          <td class="px-6 py-4">
            <%= trace.scope_name %>
          </td>
          <td class="px-6 py-4">
            <%= trace.name %>
          </td>
          <td class="px-6 py-4">
            <%= trace.start_time |> DateTime.truncate(:second) %>
          </td>
        </tr>
      </tbody>
    </table>
    """
  end

  def mount(_params, _session, socket) do
    traces = TraceKeeper.get_records()

    Phoenix.PubSub.subscribe(Latch.PubSub, "trace")

    socket =
      socket
      |> assign(:top_level_only, true)
      |> assign(:selected_trace, nil)
      |> stream_configure(:traces, dom_id: &"trace-#{&1.span_id}")
      |> stream(:traces, traces)

    {:ok, socket}
  end

  @impl true
  def handle_info({:trace, traces}, socket) do
    socket =
      Enum.reduce(traces, socket, fn trace, socket ->
        stream_insert(socket, :traces, trace, at: 0)
      end)

    {:noreply, socket}
  end

  @impl true
  def handle_event("select_trace", %{"id" => value}, socket) do
    socket =
      socket
      |> assign(:selected_trace, value)

    {:noreply, socket}
  end

  defp format_time_diff(t1, t2) do
    diff = DateTime.diff(t1, t2, :nanosecond)

    cond do
      diff < 1_000 ->
        "#{div(diff, 1)}ns"

      diff < 1_000_000 ->
        "#{div(diff, 1_000)}µs"

      diff < 1_000_000_000 ->
        "#{div(diff, 1_000_000)}ms"

      true ->
        "#{div(diff, 1_000_000_000)}s"
    end
  end
end
