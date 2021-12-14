defmodule ExPassword.Argon2.Application do
  use Application

  @impl Application
  def start(_type, _args) do
    ExPassword.Registry.register_algorithm(ExPassword.Argon2)

    Supervisor.start_link([], strategy: :one_for_one)
  end
end
