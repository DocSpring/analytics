defmodule Plausible.Shield.IPRuleCacheTest do
  use Plausible.DataCase, async: true

  alias Plausible.Shield.IPRule
  alias Plausible.Shield.IPRuleCache
  alias Plausible.Shields

  describe "public cache interface" do
    test "cache caches IP rules", %{test: test} do
      {:ok, _} =
        Supervisor.start_link([{IPRuleCache, [cache_name: test, child_id: :ip_rules_cache_id]}],
          strategy: :one_for_one,
          name: :"cache_supervisor_#{test}"
        )

      site = insert(:site, domain: "site1.example.com")

      {:ok, %{id: rid1}} = Shields.add_ip_rule(site, %{"inet" => "1.1.1.1"})
      {:ok, %{id: rid2}} = Shields.add_ip_rule(site, %{"inet" => "2.2.2.2"})

      :ok = IPRuleCache.refresh_all(cache_name: test)

      :ok = Shields.remove_ip_rule(site, rid1)

      assert IPRuleCache.size(test) == 2

      assert %IPRule{from_cache?: true, id: ^rid1} =
               IPRuleCache.get({site.domain, "1.1.1.1"}, force?: true, cache_name: test)

      assert %IPRule{from_cache?: true, id: ^rid2} =
               IPRuleCache.get({site.domain, "2.2.2.2"}, force?: true, cache_name: test)

      refute IPRuleCache.get({site.domain, "3.3.3.3"}, cache_name: test, force?: true)
    end

    test "cache allows IP lookups for sites with changed domain", %{test: test} do
      {:ok, _} = start_test_cache(test)
      site = insert(:site, domain: "new.example.com", domain_changed_from: "old.example.com")

      {:ok, _} = Shields.add_ip_rule(site, %{"inet" => "1.1.1.1"})
      :ok = IPRuleCache.refresh_all(cache_name: test)

      assert IPRuleCache.get({"old.example.com", "1.1.1.1"}, force?: true, cache_name: test)
      assert IPRuleCache.get({"new.example.com", "1.1.1.1"}, force?: true, cache_name: test)
    end

    test "refreshes only recently added rules", %{test: test} do
      {:ok, _} = start_test_cache(test)

      domain = "site1.example.com"
      site = insert(:site, domain: domain)

      cache_opts = [cache_name: test, force?: true]

      yesterday = DateTime.utc_now() |> DateTime.add(-1 * 60 * 60 * 24)

      insert(:ip_rule,
        site: site,
        inserted_at: yesterday,
        updated_at: yesterday,
        inet: "1.1.1.1"
      )

      insert(:ip_rule, site: site, inet: "2.2.2.2")

      assert IPRuleCache.get({domain, "1.1.1.1"}, cache_opts) == nil
      assert IPRuleCache.get({domain, "2.2.2.2"}, cache_opts) == nil

      assert :ok = IPRuleCache.refresh_updated_recently(cache_opts)

      refute IPRuleCache.get({domain, "1.1.1.1"}, cache_opts)
      assert %IPRule{} = IPRuleCache.get({domain, "2.2.2.2"}, cache_opts)
    end

    test "caches a site's ranges together, under both of its domains", %{test: test} do
      {:ok, _} = start_test_cache(test)
      cache_opts = [cache_name: test, force?: true]

      site = insert(:site, domain: "new.example.com", domain_changed_from: "old.example.com")
      other_site = insert(:site, domain: "other.example.com")

      {:ok, %{id: rid1}} = Shields.add_ip_rule(site, %{"inet" => "1.1.1.0/24"})
      {:ok, %{id: rid2}} = Shields.add_ip_rule(site, %{"inet" => "2001:db8::/32"})
      {:ok, _} = Shields.add_ip_rule(site, %{"inet" => "3.3.3.3"})
      {:ok, %{id: rid3}} = Shields.add_ip_rule(other_site, %{"inet" => "4.4.4.0/24"})

      :ok = IPRuleCache.refresh_all(cache_name: test)

      for domain <- ["new.example.com", "old.example.com"] do
        ranges = IPRuleCache.get_ranges(domain, cache_opts)

        assert Enum.all?(ranges, &match?(%IPRule{from_cache?: true}, &1))
        assert Enum.sort(Enum.map(ranges, & &1.id)) == Enum.sort([rid1, rid2])
        assert %IPRule{} = IPRuleCache.get({domain, "3.3.3.3"}, cache_opts)
        refute IPRuleCache.get({domain, "1.1.1.0"}, cache_opts)
      end

      assert [%IPRule{id: ^rid3}] = IPRuleCache.get_ranges("other.example.com", cache_opts)
      assert IPRuleCache.get_ranges("unknown.example.com", cache_opts) == []
    end

    test "a partial refresh leaves the ranges already cached in place", %{test: test} do
      {:ok, _} = start_test_cache(test)
      cache_opts = [cache_name: test, force?: true]

      site = insert(:site, domain: "site1.example.com")

      {:ok, %{id: rid1}} = Shields.add_ip_rule(site, %{"inet" => "1.1.1.0/24"})
      :ok = IPRuleCache.refresh_all(cache_name: test)

      {:ok, %{id: rid2}} = Shields.add_ip_rule(site, %{"inet" => "2.2.2.0/24"})
      {:ok, _} = Shields.add_ip_rule(site, %{"inet" => "3.3.3.3"})

      :ok = IPRuleCache.refresh_updated_recently(cache_opts)

      assert [%IPRule{id: ^rid1}] = IPRuleCache.get_ranges(site.domain, cache_opts)
      assert %IPRule{} = IPRuleCache.get({site.domain, "3.3.3.3"}, cache_opts)

      :ok = IPRuleCache.refresh_all(cache_name: test)

      assert Enum.sort(Enum.map(IPRuleCache.get_ranges(site.domain, cache_opts), & &1.id)) ==
               Enum.sort([rid1, rid2])
    end

    test "a removed range leaves the cache at the next full refresh", %{test: test} do
      {:ok, _} = start_test_cache(test)
      cache_opts = [cache_name: test, force?: true]

      site = insert(:site, domain: "site1.example.com")
      {:ok, _} = Shields.add_ip_rule(site, %{"inet" => "2.2.2.2"})

      {:ok, %{id: rid}} = Shields.add_ip_rule(site, %{"inet" => "1.1.1.0/24"})
      :ok = IPRuleCache.refresh_all(cache_name: test)
      assert [%IPRule{id: ^rid}] = IPRuleCache.get_ranges(site.domain, cache_opts)

      :ok = Shields.remove_ip_rule(site, rid)
      :ok = IPRuleCache.refresh_all(cache_name: test)

      assert IPRuleCache.get_ranges(site.domain, cache_opts) == []
    end

    test "is ready when a site has only ranges", %{test: test} do
      {:ok, _} = start_test_cache(test)
      site = insert(:site, domain: "site1.example.com")

      {:ok, _} = Shields.add_ip_rule(site, %{"inet" => "1.1.1.0/24"})
      :ok = IPRuleCache.refresh_all(cache_name: test)

      assert IPRuleCache.ready?(test)
    end
  end

  defp start_test_cache(cache_name) do
    %{start: {m, f, a}} = IPRuleCache.child_spec(cache_name: cache_name)
    apply(m, f, a)
  end
end
