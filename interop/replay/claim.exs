:ok = :io.setopts(:standard_io, encoding: :latin1)
alias RequestSeal.Replay.{Claim, Postgres}
Code.require_file("connection.exs", __DIR__)
{:ok, conn} = RequestSealReplayConnection.open()
[table, namespace_hex, _identifier, retain_until] = System.argv()
"0.4.1" = Application.spec(:request_seal, :vsn) |> to_string()
IO.binwrite(:stdio, "READY\n")
IO.binstream(:stdio, :line) |> Enum.each(fn line ->
  %{"identifier" => identifier, "barrier" => barrier} = :json.decode(line)
  # Both implementations block on this shared lock until the controller releases it.
  {:ok, _} = Postgrex.query(conn, "SELECT pg_advisory_lock_shared($1)", [barrier])
  try do
    key = :crypto.hash(:sha256, identifier)
    claim = struct!(Claim, namespace: Base.decode16!(namespace_hex, case: :lower), key: key, retain_until: String.to_integer(retain_until))
    result = RequestSeal.Replay.claim(Postgres.store(conn, table: table), claim, timeout: 5000)
    IO.binwrite(:stdio, ["CLAIM=", Atom.to_string(result), "\n"])
  after
    Postgrex.query(conn, "SELECT pg_advisory_unlock_shared($1)", [barrier])
  end
end)
GenServer.stop(conn)
