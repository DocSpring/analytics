defmodule Plausible.Shield.IPRuleCache do
  @moduledoc """
  Allows retrieving IP Rules by domain and IP

  A rule for one address is cached under that address. A range can't be found
  by address, so all of a site's ranges are cached together, in one list.
  """
  alias Plausible.Shield.IPRule

  import Ecto.Query
  use Plausible.Cache

  @cache_name :ip_blocklist_by_domain
  @ranges_key :ranges

  defmacrop range?(inet) do
    quote do
      fragment(
        "masklen(?) < CASE family(?) WHEN 4 THEN 32 ELSE 128 END",
        unquote(inet),
        unquote(inet)
      )
    end
  end

  @cached_schema_fields ~w(
    id
    inet
    action
  )a

  @impl true
  def name(), do: @cache_name

  @impl true
  def child_id(), do: :cache_ip_blocklist

  @impl true
  def count_all() do
    Plausible.Repo.aggregate(IPRule, :count)
  end

  @impl true
  def base_db_query() do
    from rule in IPRule,
      inner_join: s in assoc(rule, :site),
      select: {
        s.domain,
        s.domain_changed_from,
        %{struct(rule, ^@cached_schema_fields) | from_cache?: true}
      }
  end

  @spec get_ranges(String.t(), Keyword.t()) :: [IPRule.t()]
  def get_ranges(domain, opts \\ []) do
    get({domain, @ranges_key}, opts) || []
  end

  # A site's list of ranges can only be built from all of its ranges, which a
  # partial refresh doesn't load, so a new range takes effect at the next full
  # refresh.
  def refresh_updated_recently(opts) do
    query =
      from([rule, _site] in base_db_query(),
        order_by: [asc: rule.updated_at],
        where: rule.updated_at > ago(^15, "minute") and not range?(rule.inet)
      )

    refresh(:updated_recently, query, Keyword.put(opts, :delete_stale_items?, false))
  end

  @impl true
  def get_from_source({domain, @ranges_key}) do
    base_db_query()
    |> where([rule, site], range?(rule.inet) and site.domain == ^domain)
    |> Plausible.Repo.all()
    |> Enum.map(fn {_, _, rule = %IPRule{}} -> %IPRule{rule | from_cache?: false} end)
  end

  def get_from_source({domain, address}) do
    query =
      base_db_query()
      |> where([rule, site], rule.inet == ^address and site.domain == ^domain)

    case Plausible.Repo.one(query) do
      {_, _, rule = %IPRule{}} -> %IPRule{rule | from_cache?: false}
      _any -> nil
    end
  end

  @impl true
  def unwrap_cache_keys(items) do
    {ranges, addresses} =
      items
      |> Enum.flat_map(fn {domain, domain_changed_from, rule} ->
        for name <- [domain, domain_changed_from], name != nil, do: {name, rule}
      end)
      |> Enum.split_with(fn {_domain, rule} -> IPRule.range?(rule) end)

    address_items =
      Enum.map(addresses, fn {domain, rule} -> {{domain, to_string(rule.inet)}, rule} end)

    range_items =
      ranges
      |> Enum.group_by(fn {domain, _rule} -> domain end, fn {_domain, rule} -> rule end)
      |> Enum.map(fn {domain, rules} -> {{domain, @ranges_key}, rules} end)

    address_items ++ range_items
  end
end
