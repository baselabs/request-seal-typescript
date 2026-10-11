alias RequestSeal.Replay.{Claim, Postgres}
Code.require_file("connection.exs", __DIR__)
{:ok, conn} = RequestSealReplayConnection.open()
[table, namespace_hex, identifier, retain_until] = System.argv()
# Independent commitment: SHA-256 over the exact UTF-8 identifier bytes.
key = :crypto.hash(:sha256, identifier)
claim = struct!(Claim, namespace: Base.decode16!(namespace_hex, case: :lower), key: key, retain_until: String.to_integer(retain_until))
"0.4.1" = Application.spec(:request_seal, :vsn) |> to_string()
IO.puts("READY")
"go\n" = IO.gets("")
result = RequestSeal.Replay.claim(Postgres.store(conn, table: table), claim, timeout: 5000)
IO.puts("CLAIM=" <> Atom.to_string(result))
GenServer.stop(conn)
