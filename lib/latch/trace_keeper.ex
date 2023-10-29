defmodule Latch.TraceKeeper do
  use GenServer

  @table_name :traces

  # Interval for periodic cleanup
  @cleanup_interval :timer.minutes(1)

  # Threshold for record deletion in seconds
  @delete_threshold 60 * 15

  # Starts the GenServer
  def start_link(_opts) do
    GenServer.start_link(__MODULE__, :ok, name: __MODULE__)
  end

  # Initializes the GenServer
  def init(:ok) do
    table =
      :ets.new(@table_name, [
        :duplicate_bag,
        :public,
        :named_table,
        read_concurrency: true,
        write_concurrency: true
      ])

    schedule_cleanup()
    {:ok, table}
  end

  def insert_record(records) do
    first = hd(records)

    :ets.insert(
      @table_name,
      {first.trace_id, DateTime.to_unix(first.start_time), records}
    )
  end

  def get_records() do
    @table_name
    |> :ets.match({:_, :_, :"$1"})
    |> List.flatten()
  end

  def get_records(trace_id) do
    @table_name
    |> :ets.match({trace_id, :_, :"$1"})
    |> List.flatten()
  end

  # Sets up a periodic timer to clean up old records
  defp schedule_cleanup() do
    Process.send_after(self(), :cleanup, @cleanup_interval)
  end

  # Handles the :cleanup message, deletes records older than 15 minutes, and sets up the next timer
  def handle_info(:cleanup, table) do
    current_time = System.system_time(:second)
    threshold = current_time - @delete_threshold

    match_spec = [
      {{:_, :"$1", :"$2"}, [{:<, :"$1", {:const, threshold}}], [true]}
    ]

    :ets.select_delete(@table_name, match_spec)

    schedule_cleanup()
    {:noreply, table}
  end
end
