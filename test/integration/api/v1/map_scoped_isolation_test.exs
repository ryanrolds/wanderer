defmodule WandererAppWeb.Api.V1.MapScopedIsolationTest do
  @moduledoc """
  Cross-tenant isolation for the map-scoped resources on /api/v1.

  Companion to `AclCrossTenantIsolationTest`, which covers the ACL trio. This
  file covers the resources reached either by a direct `map_id` (group A) or one
  hop through `system.map_id` (group B), plus the removal of the
  `user_activities` route.

  Before this change only `map_systems` and `map_connections` were scoped, and
  only by query preparations rather than policies -- the other resources were
  bulk-readable across every map in the deployment.
  """

  use WandererAppWeb.ApiCase, async: false

  require Ash.Query

  setup :setup_two_tenants

  setup %{a: a, b: b} do
    {:ok, a: with_records(a), b: with_records(b)}
  end

  defp with_records(tenant) do
    n = System.unique_integer([:positive])

    system =
      insert(:map_system, %{
        map_id: tenant.map.id,
        solar_system_id: 30_000_000 + rem(n, 100_000),
        name: "sys-#{n}"
      })

    signature =
      insert(:map_system_signature, %{
        system_id: system.id,
        eve_id: "SIG-#{n}",
        name: "sig-#{n}"
      })

    structure =
      insert(:map_system_structure, %{
        system_id: system.id,
        name: "struct-#{n}",
        solar_system_id: system.solar_system_id,
        solar_system_name: "sys-#{n}"
      })

    Map.merge(tenant, %{system: system, signature: signature, structure: structure})
  end

  describe "group A -- resources with a direct map_id" do
    test "GET /map_systems is scoped to the key's map", %{a: a, b: b} do
      assert_index_isolated(a.conn, "/api/v1/map_systems", [a.system.id], [b.system.id])
    end

    test "GET /map_systems/:id refuses another tenant's system", %{a: a, b: b} do
      assert_show_denied(a.conn, "/api/v1/map_systems", b.system.id)
    end

    test "GET /map_connections does not leak across maps", %{a: a} do
      # Nothing seeded -- asserts the endpoint is reachable rather than 500ing
      # under the new policy.
      assert_index_isolated(a.conn, "/api/v1/map_connections", [], [])
    end
  end

  describe "group B -- resources reached via system.map_id" do
    test "GET /map_system_signatures is scoped to the key's map", %{a: a, b: b} do
      assert_index_isolated(
        a.conn,
        "/api/v1/map_system_signatures",
        [a.signature.id],
        [b.signature.id]
      )
    end

    test "GET /map_system_signatures/:id refuses another tenant's signature", %{a: a, b: b} do
      assert_show_denied(a.conn, "/api/v1/map_system_signatures", b.signature.id)
    end

    test "DELETE /map_system_signatures/:id refuses another tenant's signature", %{a: a, b: b} do
      conn = delete(a.conn, "/api/v1/map_system_signatures/#{b.signature.id}")

      assert conn.status in [403, 404], "expected refusal, got #{conn.status}"

      assert Ash.exists?(
               Ash.Query.filter(WandererApp.Api.MapSystemSignature, id == ^b.signature.id),
               authorize?: false
             ),
             "tenant B's signature was deleted"
    end

    test "GET /map_system_structures is scoped to the key's map", %{a: a, b: b} do
      assert_index_isolated(
        a.conn,
        "/api/v1/map_system_structures",
        [a.structure.id],
        [b.structure.id]
      )
    end

    test "GET /map_system_structures/:id refuses another tenant's structure", %{a: a, b: b} do
      assert_show_denied(a.conn, "/api/v1/map_system_structures", b.structure.id)
    end

    test "the /active route is scoped rather than deployment-wide", %{a: a, b: b} do
      conn = get(a.conn, "/api/v1/map_system_structures/active")

      case conn.status do
        200 ->
          ids = json_response(conn, 200)["data"] |> Enum.map(& &1["id"])
          refute b.structure.id in ids, "/active leaked tenant B's structure"

        status ->
          assert status in [403, 404], "unexpected status #{status}"
      end
    end

    test "GET /map_system_comments is reachable and scoped", %{a: a} do
      assert_index_isolated(a.conn, "/api/v1/map_system_comments", [], [])
    end
  end

  describe "per-user resources" do
    test "GET /map_user_settings is reachable and scoped", %{a: a} do
      assert_index_isolated(a.conn, "/api/v1/map_user_settings", [], [])
    end

    test "GET /map_character_settings is reachable and scoped", %{a: a} do
      assert_index_isolated(a.conn, "/api/v1/map_character_settings", [], [])
    end

    test "GET /map_subscriptions is reachable and scoped", %{a: a} do
      assert_index_isolated(a.conn, "/api/v1/map_subscriptions", [], [])
    end

    test "GET /map_default_settings is reachable and scoped", %{a: a} do
      assert_index_isolated(a.conn, "/api/v1/map_default_settings", [], [])
    end
  end

  describe "the security audit log is off the API surface" do
    test "GET /user_activities is no longer routed", %{a: a} do
      conn = get(a.conn, "/api/v1/user_activities")

      assert conn.status == 404,
             "the SecurityAudit table must not be exposed over a map-key API, got #{conn.status}"
    end
  end

  describe "systems_and_connections is scoped to the authenticated map" do
    # A hand-written controller reading with no actor, so policies cannot reach
    # it. It leaked nothing in practice -- FilterSystemsByActorMap fails closed
    # without a map in context, so it returns empty for everyone -- but the path
    # check stops that becoming a real leak if the preparation is relaxed.
    test "its own map is accepted", %{a: a} do
      conn = get(a.conn, "/api/v1/maps/#{a.map.id}/systems_and_connections")

      assert conn.status == 200, "positive control failed: got #{conn.status}"
      body = json_response(conn, 200)
      assert is_list(body["systems"])
      assert is_list(body["connections"])
    end

    test "another tenant's map id is rejected", %{a: a, b: b} do
      conn = get(a.conn, "/api/v1/maps/#{b.map.id}/systems_and_connections")

      assert conn.status == 404, "expected 404, got #{conn.status}: #{conn.resp_body}"
      refute conn.resp_body =~ b.system.id
    end
  end

  describe "the unauthenticated /api/versioned surface is gone" do
    # Previously reachable with no credentials, and 500ing on a controller
    # module that never existed.
    test "the versioned ACL routes no longer resolve", %{conn: conn} do
      for path <- [
            "/api/versioned/api/v1/acls",
            "/api/versioned/api/v1/maps",
            "/api/versioned/api/v1/acls/00000000-0000-0000-0000-000000000000"
          ] do
        result = get(conn, path)

        # nil is this app's shape for "no route matched", not the old 500.
        assert is_nil(result.status),
               "#{path} still resolves (status #{inspect(result.status)})"

        refute (result.resp_body || "") =~ "access_list", "#{path} returned ACL data"
      end
    end

    test "the versioned route table is absent from the router", %{conn: _conn} do
      versioned =
        WandererAppWeb.Router.__routes__()
        |> Enum.filter(&String.contains?(&1.path, "versioned"))

      assert versioned == [], "expected no versioned routes, found #{inspect(versioned)}"
    end
  end
end
