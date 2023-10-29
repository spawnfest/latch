defmodule Latch.TraceProcessor do
  def process_attribute(%{"key" => key, "value" => value_map}) do
    {key, hd(Map.values(value_map))}
  end

  def order_structs_by_bfs(structs) do
    root_node = Enum.find(structs, fn s -> s.parent_span_id == "" end)

    if is_nil(root_node) do
      raise "No root node found."
    end

    # Initialize the queue and BFS order list
    # Store the level of each node along with the node
    queue = [{root_node, 0}]
    bfs_order = []

    process_queue(structs, queue, bfs_order)
  end

  defp process_queue(_, [], bfs_order), do: bfs_order

  defp process_queue(structs, [{current_node, level} | rest_queue], bfs_order) do
    child_nodes = Enum.filter(structs, fn s -> s.parent_span_id == current_node.span_id end)
    child_nodes_with_level = Enum.map(child_nodes, fn s -> {s, level + 1} end)

    bfs_order =
      case Enum.count(bfs_order) do
        n when n <= level ->
          bfs_order ++ [[current_node]]

        _ ->
          List.replace_at(bfs_order, level, Enum.at(bfs_order, level) ++ [current_node])
      end

    process_queue(structs, rest_queue ++ child_nodes_with_level, bfs_order)
  end
end
