defmodule RequestSealReciprocal.MixProject do
  use Mix.Project
  def project do
    [app: :request_seal_reciprocal, version: "0.0.0", elixir: "1.20.3",
     deps: [{:request_seal, "== 0.5.2"}, {:postgrex, "~> 0.22.4"}]]
  end
  def application, do: [extra_applications: [:ssl, :public_key, :postgrex]]
end
