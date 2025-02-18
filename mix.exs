defmodule Mix.Tasks.Compile.ArgonCmake do
  def run(_) do
    {result, 0} = System.cmd("cmake", [".", "-Wno-dev"], stderr_to_stdout: true, env: [{"MIX_ENV", to_string(Mix.env())}])
    Mix.shell.info(result)
    {result, 0} = System.cmd("make", ["all"], stderr_to_stdout: true)
    Mix.shell.info(result)
    Mix.Project.build_structure()
    :ok
  end
end

defmodule ExPassword.Argon2.MixProject do
  use Mix.Project

  def project do
    [
      app: :expassword_argon2,
      version: "0.2.2",
      elixir: "~> 1.6",
      elixirc_paths: elixirc_paths(Mix.env()),
      compilers: ~W[argonCmake]a ++ Mix.compilers(),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: description(),
      package: package(),
      source_url: "https://github.com/julp/expassword_argon2",
    ]
  end

  # Configuration for the OTP application.
  #
  # Type `mix help compile.app` for more information.
  def application do
    [
      mod: {ExPassword.Argon2.Application, []},
      extra_applications: ~W[crypto logger runtime_tools]a
    ]
  end

  # Specifies which paths to compile per environment.
  defp elixirc_paths(:test), do: ~W[lib test/support]
  defp elixirc_paths(_), do: ~W[lib]

  # Specifies your project dependencies.
  #
  # Type `mix help deps` for examples and options.
  defp deps do
    [
      {:expassword, "~> 0.2"},
      {:earmark, "~> 1.4", only: :dev},
      {:ex_doc, "~> 0.22", only: :dev},
      #{:dialyxir, "~> 1.1", only: ~W[dev test]a, runtime: false},
    ]
  end

  defp description() do
    ~S"""
    The argon2 "plugin" for ExPassword (as a NIF)
    """
  end

  defp package() do
    [
      files: ~W[lib src mix.exs CMakeLists.txt README*],
      licenses: ~W[BSD],
      links: %{"GitHub" => "https://github.com/julp/expassword_argon2"},
    ]
  end
end
