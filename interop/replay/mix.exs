defmodule RequestSealReplayInterop.MixProject do
  use Mix.Project
  def project do
    [
      app: :request_seal_replay_interop,
      version: "0.0.0",
      # Keep the exact Elixir/OTP pair in sync with .tool-versions and the peer CI setup.
      elixir: "1.20.3",
      deps: [
        # Exact conformance peer identity, matching the error vocabulary release; corpus remains v0.4.0.
        {:request_seal, "== 0.4.1"},
        {:postgrex, "~> 0.22.4"}
      ]
    ]
  end
  def application, do: [extra_applications: [:postgrex]]
end
