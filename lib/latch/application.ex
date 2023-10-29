defmodule Latch.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      LatchWeb.Telemetry,
      Latch.TraceKeeper,
      # Latch.Repo,
      {DNSCluster, query: Application.get_env(:latch, :dns_cluster_query) || :ignore},
      {Phoenix.PubSub, name: Latch.PubSub},
      # Start the Finch HTTP client for sending emails
      {Finch, name: Latch.Finch},
      # Start a worker by calling: Latch.Worker.start_link(arg)
      # {Latch.Worker, arg},
      # Start to serve requests, typically the last entry
      LatchWeb.Endpoint
    ]

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: Latch.Supervisor]
    Supervisor.start_link(children, opts)
  end

  # Tell Phoenix to update the endpoint configuration
  # whenever the application is updated.
  @impl true
  def config_change(changed, _new, removed) do
    LatchWeb.Endpoint.config_change(changed, removed)
    :ok
  end
end
