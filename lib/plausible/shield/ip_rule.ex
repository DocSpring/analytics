defmodule Plausible.Shield.IPRule do
  @moduledoc """
  Schema for IP block list

  A rule covers one address or, when it has a shorter netmask, a CIDR range.
  """
  use Ecto.Schema
  import Ecto.Changeset

  @type t() :: %__MODULE__{}

  @primary_key {:id, :binary_id, autogenerate: true}
  schema "shield_rules_ip" do
    belongs_to :site, Plausible.Site
    field :inet, EctoNetwork.INET
    field :action, Ecto.Enum, values: [:deny, :allow], default: :deny
    field :description, :string
    field :added_by, :string

    # If `from_cache?` is set, the struct might be incomplete - see `Plausible.Site.Shield.Rules.IP.Cache`
    field :from_cache?, :boolean, virtual: true, default: false
    timestamps()
  end

  def changeset(rule, attrs) do
    rule
    |> cast(attrs, [:site_id, :inet, :description])
    |> validate_required([:site_id, :inet])
    |> validate_netmask(:inet)
    |> unique_constraint(:inet,
      name: :shield_rules_ip_site_id_inet_index
    )
  end

  @spec range?(t()) :: boolean()
  def range?(%__MODULE__{inet: %Postgrex.INET{address: address, netmask: netmask}}) do
    netmask < address_size(address)
  end

  @doc """
  Checks whether any of the given range rules blocks an address.

  This runs on every event of a site with ranges. The address can come from a
  request header, so it may not be an address, or even valid UTF-8.
  """
  @spec any_range_blocks?([t()], String.t()) :: boolean()
  def any_range_blocks?([], _address), do: false

  def any_range_blocks?(rules, address) do
    case :inet.parse_strict_address(:binary.bin_to_list(address)) do
      {:ok, parsed_address} ->
        Enum.any?(rules, &(&1.action == :deny and covers?(&1, parsed_address)))

      {:error, _} ->
        false
    end
  end

  # Only the bits under the netmask are compared, so host bits in a rule are ignored
  defp covers?(%__MODULE__{inet: %Postgrex.INET{address: network, netmask: netmask}}, address)
       when tuple_size(network) == tuple_size(address) do
    prefix(network, netmask) == prefix(address, netmask)
  end

  defp covers?(%__MODULE__{}, _address), do: false

  defp validate_netmask(changeset, field) do
    case get_field(changeset, field) do
      %Postgrex.INET{address: address, netmask: netmask} ->
        min = min_netmask(address)
        max = address_size(address)

        if netmask in min..max do
          changeset
        else
          add_error(changeset, field, "netmask must be between /#{min} and /#{max}")
        end

      _ ->
        changeset
    end
  end

  # A range wider than these is far more likely to be a typo than a real range
  defp min_netmask(address) when tuple_size(address) == 4, do: 8
  defp min_netmask(address) when tuple_size(address) == 8, do: 16

  defp address_size(address) when tuple_size(address) == 4, do: 32
  defp address_size(address) when tuple_size(address) == 8, do: 128

  defp prefix(address, netmask) do
    <<prefix::bitstring-size(netmask), _::bitstring>> = to_binary(address)
    prefix
  end

  defp to_binary({a, b, c, d}), do: <<a, b, c, d>>

  defp to_binary({a, b, c, d, e, f, g, h}) do
    <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>
  end
end
