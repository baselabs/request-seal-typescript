:ok = :io.setopts(:standard_io, encoding: :latin1)
Logger.configure(level: :warning)
Code.require_file("../replay/connection.exs", __DIR__)

defmodule Reciprocal do
  alias RequestSeal, as: S
  alias RequestSeal.{Custody, PublicKey, Message, Policy, Discovery, WebBotAuth}
  alias RequestSeal.Custody.Local
  alias RequestSeal.JOSE.{JWS, JWE, Nested, KeyManagement}
  @components ~s[("@method" "@scheme" "@authority" "@path" "@query" "x-exchange")]
  def b(s), do: Base.url_decode64!(s, padding: false)
  def e(s), do: Base.url_encode64(s, padding: false)
  def v({:ok, x}), do: x
  def v({:error, error}), do: throw({:peer_rule, rule(error)})
  def rule(error) do
    kind = case error.__struct__ do
      RequestSeal.Error -> "core"
      RequestSeal.JOSE.Error -> "jose"
      RequestSeal.Discovery.Error -> "discovery"
      _ -> "peer/unexpected"
    end
    kind <> if(Map.has_key?(error, :layer), do: "/#{error.layer}.#{error.reason}", else: "/#{error.reason}")
  end
  def selected(%{"algorithm" => "jws:" <> algorithm}), do: {:jws, algorithm}
  def selected(r) do
    case r["family"] do
    "jws" -> {:jws, r["algorithm"]}
    "jwe" -> {:jwe, r["algorithm"]}
    _ -> r["algorithm"]
    end
  end
  def key(r) do
    alg = String.replace_prefix(r["algorithm"], "jws:", "")
    material = cond do
      alg in ["hmac-sha256", "HS256"] -> {:hmac, :crypto.strong_rand_bytes(32)}
      alg in ["ed25519", "EdDSA"] -> {_, seed} = :crypto.generate_key(:eddsa, :ed25519); {:ed25519, seed}
      alg in ["ecdsa-p256-sha256", "ES256", "ecdsa-p384-sha384", "ES384"] ->
        curve = if alg in ["ES256", "ecdsa-p256-sha256"], do: "P-256", else: "P-384"
        {_, scalar} = :crypto.generate_key(:ecdh, if(curve == "P-256", do: :secp256r1, else: :secp384r1))
        {:ec, curve, scalar}
      true -> {:rsa, :public_key.generate_key({:rsa, 2048, 65537})}
    end
    handle = v(Local.new(selected(r), material))
    exported = case material do
      {:hmac, secret} -> %{"secret" => e(secret)}
      _ -> pub = v(Custody.public_key(handle)); %{"jwk" => v(PublicKey.export(pub, :jwk))}
    end
    {handle, exported, material}
  end
  def message(r), do: v(Message.request(r["method"], r["url"], Enum.map(r["fields"], fn [n, x] -> {n, b(x)} end), b(r["bytes"])))
  def fields(m), do: Enum.map(m.fields, fn f -> [f.name, e(f.value)] end)
  def verification_key(r) do
    if r["secret"] do
      secret = b(r["secret"])
      fn alg, bytes, signature -> S.Crypto.verify(alg, bytes, signature, {:hmac, secret}) end
    else v(PublicKey.import(r["jwk"], :jwk)) end
  end
  def jws_policy(r) do
    k = verification_key(Map.put(r, "family", "jws"))
    %{algorithms: [r["algorithm"]], timeout: 5000, key_resolver: fn _ -> {:ok, %{algorithm: r["algorithm"], key: k}} end}
  end
  def result({:ok, _}), do: %{"accepted" => true}
  def result({:error, error}), do: %{"accepted" => false, "rule" => rule(error)}
  def payload({:ok, x}, field), do: %{"accepted" => true, "bytes" => e(Map.fetch!(x, field))}
  def payload(error, _), do: result(error)
  def serve(listener, state) do
    case :ssl.transport_accept(listener, 1000) do
      {:ok, socket} ->
        spawn(fn ->
          try do
            with {:ok, socket} <- :ssl.handshake(socket, 5000), {:ok, _} <- :ssl.recv(socket, 0, 5000) do
              {body, headers} = Agent.get(state, & &1)
              wire = "HTTP/1.1 200 OK\r\n" <> Enum.map_join(headers, "", fn {n,x} -> n <> ": " <> x <> "\r\n" end) <> "content-length: #{byte_size(body)}\r\nconnection: close\r\n\r\n" <> body
              :ssl.send(socket, wire)
            end
          after
            :ssl.close(socket)
          end
        end)
        serve(listener, state)
      {:error, :timeout} -> serve(listener, state)
      {:error, :closed} -> :ok
    end
  end
  def directory(r, handle, material) do
    {port, state, _} = Process.get(:directory)
    location = "https://127.0.0.1:#{port}"
    request = v(Message.request("GET", location <> "/.well-known/http-message-signatures-directory", [], ""))
    body = :json.encode(%{"keys" => [r["jwk"]]}) |> IO.iodata_to_binary()
    response = v(Message.response(200, [{"content-type", "application/http-message-signatures-directory+json"}, {"cache-control", "max-age=120"}], body, request: request, digest: ["sha-256"]))
    pub = v(Custody.public_key(handle)); kid = v(PublicKey.thumbprint(pub)); now = String.to_integer(r["now"])
    input = ~s[("@authority";req "content-digest");created=#{now};expires=#{now + 120};keyid="#{kid}";tag="http-message-signatures-directory"]
    # Discovery possession proofs enumerate HTTP algorithms, even when the bot
    # request uses a JOSE selector. Keep the same private key in local custody.
    {proof_algorithm, proof_handle} = if is_tuple(selected(r)) do
      algorithm = case material do
        {:rsa, _} -> "rsa-pss-sha512"
        {:ec, "P-256", _} -> "ecdsa-p256-sha256"
        {:ec, "P-384", _} -> "ecdsa-p384-sha384"
        {:ed25519, _} -> "ed25519"
      end
      {algorithm, v(Local.new(algorithm, material))}
    else {selected(r), handle} end
    signed = try do
      v(S.sign(response, %{label: "directory", algorithm: proof_algorithm, signature_input: input}, proof_handle))
    after
      if proof_handle != handle, do: Local.release(proof_handle)
    end
    Agent.update(state, fn _ -> {body, Enum.map(signed.fields, &{&1.name, &1.value})} end)
  end
  def dispatch(%{"op" => "directory.read"}) do
    {_, state, _} = Process.get(:directory)
    {body, headers} = Agent.get(state, & &1)
    %{"bytes" => e(body), "fields" => Enum.map(headers, fn {n, x} -> [n, e(x)] end)}
  end
  def dispatch(%{"op" => "directory.publish"} = r) do
    {_, state, _} = Process.get(:directory)
    Agent.update(state, fn _ -> {b(r["bytes"]), Enum.map(r["fields"], fn [n, x] -> {n, b(x)} end)} end)
    %{"published" => true}
  end
  def dispatch(%{"op" => "selectors"}) do
    %{"selectors" => %{"http" => S.Crypto.algorithms(), "jws" => RequestSeal.JOSE.Support.algorithms(:jws), "jwe" => RequestSeal.JOSE.Support.algorithms(:jwe), "encs" => RequestSeal.JOSE.Support.encryption()}}
  end
  def dispatch(%{"op" => "directory.start"} = r) do
    [{:Certificate, cert, :not_encrypted}] = :public_key.pem_decode(b(r["cert"]))
    [{tag, key, :not_encrypted}] = :public_key.pem_decode(b(r["key"]))
    {:ok, socket} = :ssl.listen(0, [:binary, ip: {127, 0, 0, 1}, active: false, reuseaddr: true, cert: cert, key: {tag, key}])
    {:ok, {_, port}} = :ssl.sockname(socket)
    {:ok, state} = Agent.start_link(fn -> nil end)
    spawn_link(fn -> serve(socket, state) end)
    Process.put(:directory, {port, state, socket})
    %{"location" => "https://127.0.0.1:#{port}", "ca" => r["ca"]}
  end
  def dispatch(%{"op" => "sign"} = r) do
    {h, exported, material} = key(r)
    try do
      output = case r["family"] do
        "jws" -> %{"compact" => v(JWS.sign([{"alg", r["algorithm"]}], b(r["bytes"]), h))}
        "web_bot_auth" ->
          directory(Map.merge(r, exported), h, material)
          pub = v(Custody.public_key(h)); now = String.to_integer(r["now"])
          signed = v(WebBotAuth.sign(message(r), %{label: "agent", agent: %{type: :directory, location: r["location"]}, key: pub, algorithm: selected(r), created: now, expires: now + 60, nonce: r["nonce"], components: @components}, fn _, bytes -> Custody.sign(h, bytes) end))
          %{"fields" => fields(signed)}
        _ ->
          now = String.to_integer(r["now"])
          input = @components <> ~s[;created=#{now};expires=#{now + 60};nonce="#{r["nonce"]}";alg="#{r["algorithm"]}";keyid="exchange"]
          signed = v(S.sign(message(r), %{label: "sig", algorithm: r["algorithm"], signature_input: input}, h))
          %{"fields" => fields(signed)}
      end
      Map.merge(output, exported)
    after Local.release(h) end
  end
  def dispatch(%{"op" => "verify", "family" => "web_bot_auth"} = r) do
    now = String.to_integer(r["now"])
    source = v(Discovery.Source.new(%{type: :directory, location: r["location"], cacerts: [b(r["ca"])], permitted_addresses: [{127, 0, 0, 1}]}))
    set = v(Discovery.fetch(source, clock: fn -> now end))
    policy = v(WebBotAuth.Policy.new(%{algorithms: [selected(r)], agents: fn _ -> {:ok, set} end, cache: nil, freshness: %{clock: fn -> now end, max_age: 60, skew: 0}, content: :not_required, replay: :not_required}))
    Map.put(result(WebBotAuth.verify(message(r), policy)), "proof", Atom.to_string(set.proof))
  end
  def dispatch(%{"op" => "verify"} = r) do
    k = verification_key(r)
    try do
      if r["family"] == "jws" do
        payload(JWS.verify(r["compact"], %{algorithms: [r["algorithm"]], timeout: 5000, key_resolver: fn _ -> {:ok, %{algorithm: r["algorithm"], key: k}} end}), :payload)
      else
        now = String.to_integer(r["now"])
        policy = v(Policy.new(%{algorithms: [r["algorithm"]], components: @components, key_resolver: fn _ ->
          {:ok, %{algorithm: r["algorithm"], key: k}}
        end, freshness: %{clock: fn -> now end, max_age: 60, skew: 0, require_expires: true}, content: :not_required, replay: :not_required}))
        result(S.verify(message(r), policy, label: "sig"))
      end
    after if is_struct(k, RequestSeal.KeyHandle), do: Local.release(k) end
  end
  def dispatch(%{"op" => "prepare"} = r) do
    if String.starts_with?(r["algorithm"], "RSA") do
      {h, exported, _} = key(Map.put(r, "family", "jwe"))
      Process.put({:recipient, r["id"]}, h)
      Map.put(exported, "keyId", r["id"])
    else
      %{"secret" => e(:crypto.strong_rand_bytes(if(r["algorithm"] == "A128GCMKW", do: 16, else: 32)))}
    end
  end
  def dispatch(%{"op" => "encrypt"} = r) do
    recipient = cond do
      String.starts_with?(r["algorithm"], "RSA") -> v(PublicKey.import(r["jwk"], :jwk))
      r["algorithm"] == "dir" -> nil
      true -> fn alg, cek -> KeyManagement.wrap(alg, cek, %{}, {:aes, b(r["secret"])}) end
    end
    # The JWE worker owns its fresh CEK. Provision direct custody through a local agent.
    {:ok, direct} = Agent.start_link(fn -> nil end)
    recipient = if r["algorithm"] == "dir", do: fn _, cek -> Agent.update(direct, fn _ -> cek end); {:ok, %{encrypted_key: "", header: %{}}} end, else: recipient
    try do
      header = [{"alg", r["algorithm"]}, {"enc", r["enc"]}] ++ if(r["family"] == "nested", do: [{"cty", "JWS"}], else: [])
      token = v(JWE.encrypt(header, b(r["bytes"]), recipient))
      secret = if r["algorithm"] == "dir", do: e(Agent.get(direct, & &1)), else: r["secret"]
      Map.merge(%{"compact" => token}, if(secret, do: %{"secret" => secret}, else: %{}))
    after Agent.stop(direct) end
  end
  def dispatch(%{"op" => "decrypt"} = r) do
    h = if String.starts_with?(r["algorithm"], "RSA"), do: Process.get({:recipient, r["keyId"]})
    resolver = if h, do: fn _ -> {:ok, %{algorithm: r["algorithm"], key: h}} end, else: fn _ -> {:ok, %{algorithm: r["algorithm"], unwrap: fn bytes, header -> KeyManagement.unwrap(r["algorithm"], bytes, header, {if(r["algorithm"] == "dir", do: :cek, else: :aes), b(r["secret"])}) end}} end
    policy = %{algorithms: [r["algorithm"]], encryption: [r["enc"]], max_plaintext: 1048576, timeout: 5000, key_resolver: resolver}
    try do
      if r["family"] == "nested" do
        case Nested.verify(r["compact"], policy, jws_policy(r |> Map.delete("secret") |> Map.put("algorithm", "EdDSA")), content_types: ["JWS"]) do
          {:ok, x} -> payload({:ok, x.jws}, :payload)
          error -> result(error)
        end
      else payload(JWE.decrypt(r["compact"], policy), :plaintext) end
    after :ok end
  end
  def dispatch(%{"op" => "release"} = r) do
    if h = Process.delete({:recipient, r["keyId"]}), do: Local.release(h)
    %{"released" => true}
  end
  def dispatch(%{"op" => "claim"} = r) do
    {:ok, conn} = RequestSealReplayConnection.open()
    try do
      claim = struct!(RequestSeal.Replay.Claim, namespace: b(r["namespace"]), key: :crypto.hash(:sha256, r["nonce"]), retain_until: String.to_integer(r["retainUntil"]))
      answer = RequestSeal.Replay.claim(RequestSeal.Replay.Postgres.store(conn, table: r["table"]), claim, timeout: 5000)
      %{"claim" => Atom.to_string(answer)}
    after GenServer.stop(conn) end
  end
  def run do
    "0.4.1" = Application.spec(:request_seal, :vsn) |> to_string()
    IO.binwrite(:stdio, [:json.encode(%{"ready" => true, "language" => "elixir", "version" => "0.4.1"}), "\n"])
    IO.binstream(:stdio, :line) |> Enum.each(fn line ->
      r = :json.decode(line)
      response = try do dispatch(r) catch
        {:peer_rule, rule} -> %{"accepted" => false, "rule" => rule}
        kind, error -> %{"accepted" => false, "rule" => "peer/#{kind}: #{inspect(error)}"}
      end
      IO.binwrite(:stdio, [:json.encode(Map.put(response, "id", r["id"])), "\n"])
    end)
    if d = Process.get(:directory), do: :ssl.close(elem(d, 2))
  end
end
Reciprocal.run()
