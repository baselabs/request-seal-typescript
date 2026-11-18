defmodule RequestSealReplayInterop.MixProject do
  use Mix.Project
  def project do
    [
      app: :request_seal_replay_interop,
      version: "0.0.0",
      # Keep the exact Elixir/OTP pair in sync with .tool-versions and the peer CI setup.
      elixir: "1.20.3",
      deps: [
        # Exact published conformance peer, matching the corpus and error vocabulary release.
        {:request_seal, "== 1.0.0"},
        {:postgrex, "~> 0.22.4"},
        {:mix_audit, "~> 2.1", only: [:dev, :test], runtime: false}
      ]
    ]
  end
  def application, do: [extra_applications: [:postgrex]]
end
