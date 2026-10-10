# Parse pinned public source without loading or executing its modules.
defmodule RequestSealReasonAST do
  import Kernel, except: [node: 1]
  def node({{:., _, [receiver, name]}, meta, args}) when is_list(args),
    do: %{call: Atom.to_string(name), receiver: Macro.to_string(receiver), line: meta[:line] || 0, args: Enum.map(args, &node/1), expression: ""}
  def node({:__aliases__, _, _} = value), do: %{module: Macro.to_string(value)}
  def node({:%, meta, args} = value),
    do: %{call: "%", line: meta[:line] || 0, args: Enum.map(args, &node/1), expression: Macro.to_string(value)}
  def node({name, meta, args}) when is_atom(name) and is_list(args),
    do: %{call: Atom.to_string(name), line: meta[:line] || 0, args: Enum.map(args, &node/1), expression: ""}
  def node({name, _, context}) when is_atom(name) and is_atom(context), do: %{var: Atom.to_string(name)}
  def node(value) when is_tuple(value), do: %{tuple: value |> Tuple.to_list() |> Enum.map(&node/1)}
  def node(value) when is_list(value), do: Enum.map(value, &node/1)
  def node(value) when is_atom(value), do: %{atom: Atom.to_string(value)}
  def node(value) when is_binary(value), do: %{string: value}
  def node(value), do: value
end
sources = :json.decode(IO.read(:stdio, :eof))
output = Map.new(sources, fn {path, source} -> {path, RequestSealReasonAST.node(Code.string_to_quoted!(source))} end)
IO.write(:json.encode(output))
