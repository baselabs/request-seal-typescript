defmodule RequestSealReciprocal.MixProject do
  use Mix.Project
  def project do
    [app: :request_seal_reciprocal, version: "0.0.0", elixir: "1.20.3",
     deps: [{:request_seal, "== 1.0.0"}, {:postgrex, "~> 0.22.4"},
            {:mix_audit, "~> 2.1", only: [:dev, :test], runtime: false}]]
  end
  def application, do: [extra_applications: [:ssl, :public_key, :postgrex]]
end
