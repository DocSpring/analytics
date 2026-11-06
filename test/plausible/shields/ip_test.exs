defmodule Plausible.Shields.IPTest do
  use Plausible.DataCase
  import Plausible.Shields

  alias Plausible.Shield.IPRule

  setup do
    site = insert(:site)
    {:ok, %{site: site}}
  end

  describe "add_ip_rule/2" do
    test "no input", %{site: site} do
      assert {:error, changeset} = add_ip_rule(site, %{})
      assert changeset.errors == [inet: {"can't be blank", [validation: :required]}]
      refute changeset.valid?
    end

    test "accepts CIDR ranges", %{site: site} do
      assert {:ok, rule} = add_ip_rule(site, %{"inet" => "127.0.0.0/24"})
      assert rule.inet == %Postgrex.INET{address: {127, 0, 0, 0}, netmask: 24}

      assert {:ok, _} = add_ip_rule(site, %{"inet" => "127.0.0.0/32"})
      assert {:ok, _} = add_ip_rule(site, %{"inet" => "10.0.0.0/8"})
      assert {:ok, _} = add_ip_rule(site, %{"inet" => "2001:db8::/32"})
      assert {:ok, _} = add_ip_rule(site, %{"inet" => "2001::/16"})
    end

    test "rejects ranges wider than /8 for IPv4", %{site: site} do
      for inet <- ["0.0.0.0/0", "10.0.0.0/7"] do
        assert {:error, changeset} = add_ip_rule(site, %{"inet" => inet})
        assert changeset.errors == [inet: {"netmask must be between /8 and /32", []}]
      end
    end

    test "rejects ranges wider than /16 for IPv6", %{site: site} do
      for inet <- ["::/0", "2001::/15"] do
        assert {:error, changeset} = add_ip_rule(site, %{"inet" => inet})
        assert changeset.errors == [inet: {"netmask must be between /16 and /128", []}]
      end
    end

    test "rejects netmasks too long for the address", %{site: site} do
      assert {:error, %{valid?: false}} = add_ip_rule(site, %{"inet" => "127.0.0.0/33"})
      assert {:error, %{valid?: false}} = add_ip_rule(site, %{"inet" => "2001:db8::/129"})
    end

    test "incorrect ip", %{site: site} do
      assert {:error, changeset} = add_ip_rule(site, %{"inet" => "999.999.999.999"})

      assert changeset.errors == [
               inet: {"is invalid", [{:type, EctoNetwork.INET}, {:validation, :cast}]}
             ]

      refute changeset.valid?
    end

    test "non-strict IPs", %{site: site} do
      assert {:error, _} = add_ip_rule(site, %{"inet" => "111"})
    end

    test "double insert", %{site: site} do
      assert {:ok, _} = add_ip_rule(site, %{"inet" => "0.0.0.111"})
      assert {:error, changeset} = add_ip_rule(site, %{"inet" => "0.0.0.111"})
      refute changeset.valid?

      assert changeset.errors == [
               inet:
                 {"has already been taken",
                  [
                    {:constraint, :unique},
                    {:constraint_name, "shield_rules_ip_site_id_inet_index"}
                  ]}
             ]
    end

    test "ipv6", %{site: site} do
      assert {:ok, rule} =
               add_ip_rule(site, %{"inet" => "2001:0000:130F:0000:0000:09C0:876A:130B"})

      assert ^rule = Repo.get(Plausible.Shield.IPRule, rule.id)
    end

    test "ipv4", %{site: site} do
      assert {:ok, rule} =
               add_ip_rule(site, %{"inet" => "1.1.1.1"})

      assert ^rule = Repo.get(Plausible.Shield.IPRule, rule.id)
    end

    test "over limit", %{site: site} do
      for i <- 1..maximum_ip_rules() do
        assert {:ok, _} =
                 add_ip_rule(site, %{"inet" => "1.1.1.#{i}"})
      end

      assert count_ip_rules(site) == maximum_ip_rules()

      assert {:error, changeset} =
               add_ip_rule(site, %{"inet" => "1.1.1.31"})

      refute changeset.valid?
      assert changeset.errors == [inet: {"maximum reached", []}]
    end

    test "with added_by", %{site: site} do
      assert {:ok, rule} =
               add_ip_rule(site, %{"inet" => "1.1.1.1"},
                 added_by: build(:user, name: "Joe", email: "joe@example.com")
               )

      assert rule.added_by == "Joe <joe@example.com>"
    end
  end

  describe "remove_ip_rule/2" do
    test "is idempontent", %{site: site} do
      {:ok, rule} = add_ip_rule(site, %{"inet" => "127.0.0.1"})
      assert remove_ip_rule(site, rule.id) == :ok
      refute Repo.get(Plausible.Shield.IPRule, rule.id)
      assert remove_ip_rule(site, rule.id) == :ok
    end
  end

  describe "list_ip_rules/1" do
    test "empty", %{site: site} do
      assert(list_ip_rules(site) == [])
    end

    @tag :slow
    test "many", %{site: site} do
      {:ok, r1} = add_ip_rule(site, %{"inet" => "127.0.0.1"})
      :timer.sleep(1000)
      {:ok, r2} = add_ip_rule(site, %{"inet" => "127.0.0.2"})
      assert [^r2, ^r1] = list_ip_rules(site)
    end
  end

  describe "count_ip_rules/1" do
    test "counts", %{site: site} do
      assert count_ip_rules(site) == 0
      {:ok, _} = add_ip_rule(site, %{"inet" => "127.0.0.1"})
      assert count_ip_rules(site) == 1
      {:ok, _} = add_ip_rule(site, %{"inet" => "127.0.0.2"})
      assert count_ip_rules(site) == 2
    end
  end

  describe "IP Rules" do
    test "end to end", %{site: site} do
      site2 = insert(:site)

      assert count_ip_rules(site.id) == 0
      assert list_ip_rules(site.id) == []

      assert {:ok, rule} =
               add_ip_rule(site.id, %{"inet" => "127.0.0.1", "description" => "Localhost"})

      add_ip_rule(site2, %{"inet" => "127.0.0.1", "description" => "Localhost"})

      assert count_ip_rules(site) == 1
      assert [^rule] = list_ip_rules(site)
      assert rule.inet == %Postgrex.INET{address: {127, 0, 0, 1}, netmask: 32}
      assert rule.description == "Localhost"
      assert rule.action == :deny
      refute rule.from_cache?
      assert ip_blocked?(site, "127.0.0.1")
      refute ip_blocked?(site, "127.0.0.2")
    end

    test "a range blocks every address inside it and none outside", %{site: site} do
      {:ok, _} = add_ip_rule(site, %{"inet" => "203.0.113.0/24"})

      assert ip_blocked?(site, "203.0.113.0")
      assert ip_blocked?(site, "203.0.113.7")
      assert ip_blocked?(site, "203.0.113.255")
      refute ip_blocked?(site, "203.0.112.255")
      refute ip_blocked?(site, "203.0.114.0")
    end

    test "a range can end part way through an octet", %{site: site} do
      {:ok, _} = add_ip_rule(site, %{"inet" => "198.51.100.64/26"})

      assert ip_blocked?(site, "198.51.100.64")
      assert ip_blocked?(site, "198.51.100.127")
      refute ip_blocked?(site, "198.51.100.63")
      refute ip_blocked?(site, "198.51.100.128")
    end

    test "a range ignores host bits", %{site: site} do
      {:ok, _} = add_ip_rule(site, %{"inet" => "203.0.113.7/24"})

      assert ip_blocked?(site, "203.0.113.200")
      refute ip_blocked?(site, "203.0.114.7")
    end

    test "IPv6 ranges, including one with a netmask of 32", %{site: site} do
      {:ok, _} = add_ip_rule(site, %{"inet" => "2001:db8::/32"})

      assert ip_blocked?(site, "2001:db8::")
      assert ip_blocked?(site, "2001:db8:ffff::1")
      refute ip_blocked?(site, "2001:db9::1")
    end

    test "a range only matches addresses of its own family", %{site: site} do
      # 1.0.0.0/8 and 100::1 share their first 8 bits
      {:ok, _} = add_ip_rule(site, %{"inet" => "1.0.0.0/8"})

      assert ip_blocked?(site, "1.2.3.4")
      refute ip_blocked?(site, "100::1")
    end

    test "a range only applies to its own site", %{site: site} do
      other_site = insert(:site)
      {:ok, _} = add_ip_rule(site, %{"inet" => "203.0.113.0/24"})

      assert ip_blocked?(site, "203.0.113.7")
      refute ip_blocked?(other_site, "203.0.113.7")
    end

    test "an address rule that allows traffic wins over a range", %{site: site} do
      {:ok, _} = add_ip_rule(site, %{"inet" => "203.0.113.0/24"})
      insert(:ip_rule, site: site, inet: "203.0.113.7", action: :allow)

      refute ip_blocked?(site, "203.0.113.7")
      assert ip_blocked?(site, "203.0.113.8")
    end

    test "a removed range stops blocking", %{site: site} do
      {:ok, rule} = add_ip_rule(site, %{"inet" => "203.0.113.0/24"})
      assert ip_blocked?(site, "203.0.113.7")

      :ok = remove_ip_rule(site, rule.id)
      refute ip_blocked?(site, "203.0.113.7")
    end
  end

  describe "IPRule.any_range_blocks?/2" do
    setup do
      rule = %IPRule{
        inet: %Postgrex.INET{address: {203, 0, 113, 0}, netmask: 24},
        action: :deny
      }

      {:ok, %{rule: rule}}
    end

    test "finds an address in any of the ranges", %{rule: rule} do
      other_rule = %IPRule{
        inet: %Postgrex.INET{address: {198, 51, 100, 0}, netmask: 24},
        action: :deny
      }

      assert IPRule.any_range_blocks?([rule, other_rule], "198.51.100.7")
      refute IPRule.any_range_blocks?([rule, other_rule], "192.0.2.7")
    end

    test "is false without any ranges" do
      refute IPRule.any_range_blocks?([], "203.0.113.7")
    end

    test "ignores ranges that allow traffic", %{rule: rule} do
      refute IPRule.any_range_blocks?([%{rule | action: :allow}], "203.0.113.7")
    end

    test "is false, and doesn't raise, for anything that isn't an address", %{rule: rule} do
      for address <- ["", "not-an-ip", "203.0.113", "203.0.113.7/24", <<255, 254>>] do
        refute IPRule.any_range_blocks?([rule], address)
      end
    end
  end
end
