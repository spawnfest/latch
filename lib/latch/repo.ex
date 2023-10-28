defmodule Latch.Repo do
  use Ecto.Repo,
    otp_app: :latch,
    adapter: Ecto.Adapters.Postgres
end
