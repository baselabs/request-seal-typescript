defmodule RequestSealReplayConnection do
  def open do
    uri = URI.parse(System.fetch_env!("REQUESTSEAL_REPLAY_PG_URL"))
    if not is_binary(uri.userinfo) or uri.userinfo == "" do
      IO.binwrite(:stderr, "Invalid replay database URL: userinfo is required\n")
      System.halt(1)
    end
    {:ok, _} = Application.ensure_all_started(:postgrex)
    [user | password] = String.split(uri.userinfo, ":", parts: 2)
    # Dynamic dispatch keeps the URL rejection usable before dependencies load.
    apply(Postgrex, :start_link, [[
      hostname: uri.host, port: uri.port || 5432,
      database: uri.path |> String.trim_leading("/") |> URI.decode(), username: URI.decode(user),
      password: case password do [value] -> URI.decode(value); [] -> nil end
    ]])
  end
end
