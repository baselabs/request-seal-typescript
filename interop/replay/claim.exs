alias RequestSeal.Replay.{Claim, Postgres}
uri = URI.parse(System.fetch_env!("REQUESTSEAL_REPLAY_PG_URL"))
if not is_binary(uri.userinfo) or uri.userinfo == "" do
  IO.puts(:stderr, "Invalid replay database URL: userinfo is required")
  System.halt(1)
end
{:ok, _} = Application.ensure_all_started(:postgrex)
[user | password] = String.split(uri.userinfo, ":", parts: 2)
{:ok, conn} = Postgrex.start_link(
  hostname: uri.host,
  port: uri.port || 5432,
  database: uri.path |> String.trim_leading("/") |> URI.decode(),
  username: URI.decode(user),
  password: case password do [value] -> URI.decode(value); [] -> nil end
)
[table, namespace_hex, identifier, retain_until] = System.argv()
# Independent commitment: SHA-256 over the exact UTF-8 identifier bytes.
key = :crypto.hash(:sha256, identifier)
claim = struct!(Claim, namespace: Base.decode16!(namespace_hex, case: :lower), key: key, retain_until: String.to_integer(retain_until))
"0.4.0" = Application.spec(:request_seal, :vsn) |> to_string()
IO.puts("READY")
"go\n" = IO.gets("")
result = RequestSeal.Replay.claim(Postgres.store(conn, table: table), claim, timeout: 5000)
IO.puts("CLAIM=" <> Atom.to_string(result))
GenServer.stop(conn)
