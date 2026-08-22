defmodule WandererAppWeb.Api.V1.AclCrossTenantIsolationTest do
  @moduledoc """
  Cross-tenant authorization tests for the ACL surface of the /api/v1 JSON:API.

  Regression tests for the reported vulnerability: a map API key was accepted by
  `CheckJsonApiAuth` but no Ash resource declared any policy, so any valid map
  key could read every ACL in the deployment and add itself as `:admin` to any
  of them.

  Two independent tenants, A and B. Every request is made with A's map API key.
  Nothing belonging to B may be readable or writable.

  Every denial assertion is paired with a positive control -- a policy that
  denies everything would otherwise pass this entire file.
  """

  use WandererAppWeb.ApiCase, async: false

  require Ash.Query

  alias WandererApp.Api.AccessList
  alias WandererApp.Api.AccessListMember
  alias WandererApp.Api.MapAccessList

  setup :setup_two_tenants

  # authorize?: false on purpose -- asserts what is actually in the database
  # after a request that should have been refused.
  defp reload!(resource, id) do
    resource
    |> Ash.Query.filter(id == ^id)
    |> Ash.read_one!(authorize?: false)
  end

  defp jsonapi(type, attributes, id \\ nil) do
    data =
      %{"type" => type, "attributes" => attributes}
      |> then(fn d -> if id, do: Map.put(d, "id", id), else: d end)

    %{"data" => data}
  end

  # CheckJsonApiAuth falls back to the session without a bearer token, giving a
  # {:user, _} principal -- the only one allowed to create ACLs.
  defp session_conn(t) do
    Phoenix.ConnTest.build_conn()
    |> Plug.Test.init_test_session(user_id: t.user.id)
    |> Plug.Conn.put_req_header("content-type", "application/vnd.api+json")
  end

  describe "creating an access list" do
    test "a map API key cannot create one at all", %{a: a} do
      conn =
        post(
          a.conn,
          "/api/v1/access_lists",
          jsonapi("access_lists", %{"name" => "by-map-key", "owner_id" => a.character.id})
        )

      assert conn.status in [403, 404],
             "a bearer map key must not mint ACLs -- a new ACL is bound to no map, so no map-scoped policy could govern it. Got #{conn.status}"
    end

    test "a session user can create one owned by their own character", %{a: a} do
      conn =
        post(
          session_conn(a),
          "/api/v1/access_lists",
          jsonapi("access_lists", %{"name" => "legitimate", "owner_id" => a.character.id})
        )

      assert conn.status in [200, 201],
             "positive control failed: got #{conn.status}: #{conn.resp_body}"
    end

    test "a session user cannot create one owned by someone else's character", %{a: a, b: b} do
      conn =
        post(
          session_conn(a),
          "/api/v1/access_lists",
          jsonapi("access_lists", %{"name" => "spoofed", "owner_id" => b.character.id})
        )

      assert conn.status in [400, 403, 422],
             "owner_id must be constrained to the caller's own characters, got #{conn.status}: #{conn.resp_body}"

      refute Ash.exists?(
               Ash.Query.filter(AccessList, owner_id == ^b.character.id and name == "spoofed"),
               authorize?: false
             ),
             "an ACL was created owned by another user's character"
    end

    test "api_key cannot be supplied by the client on create", %{a: a} do
      conn =
        post(
          session_conn(a),
          "/api/v1/access_lists",
          jsonapi("access_lists", %{
            "name" => "keyed",
            "owner_id" => a.character.id,
            "api_key" => "attacker-chosen-key"
          })
        )

      # Schema rejection or silent drop are both fine; what must not happen is
      # the client's key landing on the record, since it authenticates the
      # legacy /api/acls/* surface.
      refute Ash.exists?(
               Ash.Query.filter(AccessList, api_key == "attacker-chosen-key"),
               authorize?: false
             ),
             "a client-supplied api_key was persisted (status #{conn.status})"
    end
  end

  describe "positive control: a map key retains access to its own map's ACLs" do
    test "lists its own bound ACL", %{a: a} do
      ids = assert_index_isolated(a.conn, "/api/v1/access_lists", [a.acl.id], [])
      assert length(ids) == 1
    end

    test "reads its own bound ACL directly", %{a: a} do
      response =
        a.conn
        |> get("/api/v1/access_lists/#{a.acl.id}")
        |> json_response(200)

      assert response["data"]["id"] == a.acl.id
    end

    test "lists its own ACL's members", %{a: a} do
      assert_index_isolated(a.conn, "/api/v1/access_list_members", [a.acl_member.id], [])
    end

    test "adds a member to its own bound ACL", %{a: a} do
      conn =
        post(
          a.conn,
          "/api/v1/access_list_members",
          jsonapi("access_list_members", %{
            "access_list_id" => a.acl.id,
            "name" => "legitimate-addition",
            "eve_character_id" => "95000001",
            "role" => "member"
          })
        )

      assert conn.status in [200, 201],
             "map key should still manage its own ACL's members, got #{conn.status}: #{conn.resp_body}"
    end

    test "renames its own bound ACL", %{a: a} do
      conn =
        patch(
          a.conn,
          "/api/v1/access_lists/#{a.acl.id}",
          jsonapi("access_lists", %{"name" => "renamed-by-owner"}, a.acl.id)
        )

      assert conn.status == 200, "expected 200, got #{conn.status}: #{conn.resp_body}"
      assert reload!(AccessList, a.acl.id).name == "renamed-by-owner"
    end
  end

  describe "ACL reads are scoped to the key's map" do
    test "GET /access_lists does not leak another tenant's ACL", %{a: a, b: b} do
      assert_index_isolated(a.conn, "/api/v1/access_lists", [a.acl.id], [b.acl.id])
    end

    test "GET /access_lists/:id refuses another tenant's ACL", %{a: a, b: b} do
      assert_show_denied(a.conn, "/api/v1/access_lists", b.acl.id)
    end

    test "GET /access_list_members does not leak another tenant's members", %{a: a, b: b} do
      assert_index_isolated(
        a.conn,
        "/api/v1/access_list_members",
        [a.acl_member.id],
        [b.acl_member.id]
      )
    end

    test "GET /access_list_members/:id refuses another tenant's member", %{a: a, b: b} do
      assert_show_denied(a.conn, "/api/v1/access_list_members", b.acl_member.id)
    end

    test "filtering cannot be used to reach another tenant's ACL", %{a: a, b: b} do
      ids =
        a.conn
        |> get("/api/v1/access_lists?filter[id]=#{b.acl.id}")
        |> json_response(200)
        |> Map.fetch!("data")
        |> Enum.map(& &1["id"])

      refute b.acl.id in ids
      assert ids == []
    end
  end

  describe "privilege escalation into another tenant's ACL is refused" do
    test "cannot add self as :admin to another tenant's ACL", %{a: a, b: b} do
      before_count = member_count(b.acl.id)

      conn =
        post(
          a.conn,
          "/api/v1/access_list_members",
          jsonapi("access_list_members", %{
            "access_list_id" => b.acl.id,
            "name" => "pwn",
            "eve_character_id" => "90000001",
            "role" => "admin"
          })
        )

      assert conn.status in [403, 404],
             "expected refusal, got #{conn.status}: #{conn.resp_body}"

      assert member_count(b.acl.id) == before_count,
             "a member was created on tenant B's ACL despite the refusal"
    end

    test "cannot promote a member of another tenant's ACL", %{a: a, b: b} do
      conn =
        patch(
          a.conn,
          "/api/v1/access_list_members/#{b.acl_member.id}",
          jsonapi("access_list_members", %{"role" => "admin"}, b.acl_member.id)
        )

      assert conn.status in [403, 404], "expected refusal, got #{conn.status}"
      assert reload!(AccessListMember, b.acl_member.id).role == :admin
    end

    test "cannot delete a member of another tenant's ACL", %{a: a, b: b} do
      conn = delete(a.conn, "/api/v1/access_list_members/#{b.acl_member.id}")

      assert conn.status in [403, 404], "expected refusal, got #{conn.status}"
      refute is_nil(reload!(AccessListMember, b.acl_member.id)), "member was deleted"
    end

    # Two separate controls, one assertion each: the policy, and the accept list.
    test "the policy refuses any write to another tenant's ACL", %{a: a, b: b} do
      original_name = reload!(AccessList, b.acl.id).name

      conn =
        patch(
          a.conn,
          "/api/v1/access_lists/#{b.acl.id}",
          jsonapi("access_lists", %{"name" => "hacked"}, b.acl.id)
        )

      assert conn.status in [403, 404],
             "a valid-shaped write to tenant B's ACL must be refused by policy, got #{conn.status}: #{conn.resp_body}"

      assert reload!(AccessList, b.acl.id).name == original_name
    end

    test "owner_id is rejected outright by the routed update action", %{a: a, b: b} do
      original_owner = reload!(AccessList, b.acl.id).owner_id

      conn =
        patch(
          a.conn,
          "/api/v1/access_lists/#{b.acl.id}",
          jsonapi("access_lists", %{"owner_id" => a.character.id}, b.acl.id)
        )

      # 400 means the schema refused the attribute before the policy ran. Either
      # layer refusing is fine; what matters is that ownership does not move.
      assert conn.status in [400, 403, 404, 422], "expected refusal, got #{conn.status}"
      assert reload!(AccessList, b.acl.id).owner_id == original_owner
    end

    test "owner_id is not writable even on the key's own ACL", %{a: a, b: b} do
      original_owner = reload!(AccessList, a.acl.id).owner_id

      patch(
        a.conn,
        "/api/v1/access_lists/#{a.acl.id}",
        jsonapi("access_lists", %{"owner_id" => b.character.id}, a.acl.id)
      )

      assert reload!(AccessList, a.acl.id).owner_id == original_owner,
             "owner_id must not be accepted by the JSON:API-routed update action"
    end

    test "cannot delete another tenant's ACL", %{a: a, b: b} do
      conn = delete(a.conn, "/api/v1/access_lists/#{b.acl.id}")

      assert conn.status in [403, 404], "expected refusal, got #{conn.status}"
      refute is_nil(reload!(AccessList, b.acl.id)), "tenant B's ACL was deleted"
    end
  end

  # ---------------------------------------------------------------------------
  # The bind-then-read bypass. The single most important case in this file:
  # without it, every assertion above can be defeated in two requests.
  # ---------------------------------------------------------------------------

  # Without this, every assertion above can be defeated in two requests.
  describe "the bind-then-read bypass is closed" do
    test "cannot bind another tenant's ACL to its own map, and still cannot read it",
         %{a: a, b: b} do
      conn =
        post(
          a.conn,
          "/api/v1/map_access_lists",
          jsonapi("map_access_lists", %{
            "map_id" => a.map.id,
            "access_list_id" => b.acl.id
          })
        )

      assert conn.status in [403, 404],
             "binding a foreign ACL must be refused, got #{conn.status}: #{conn.resp_body}"

      refute binding_exists?(a.map.id, b.acl.id),
             "a map_access_lists row was created despite the refusal"

      # The point: even after attempting the bind, B's ACL stays invisible.
      assert_index_isolated(a.conn, "/api/v1/access_lists", [a.acl.id], [b.acl.id])

      assert_index_isolated(
        a.conn,
        "/api/v1/access_list_members",
        [a.acl_member.id],
        [b.acl_member.id]
      )
    end

    test "cannot detach another tenant's ACL from their map", %{a: a, b: b} do
      conn = delete(a.conn, "/api/v1/map_access_lists/#{b.map_acl.id}")

      assert conn.status in [403, 404], "expected refusal, got #{conn.status}"
      assert binding_exists?(b.map.id, b.acl.id), "tenant B's binding was removed"
    end

    test "a bearer map key cannot unbind its own map's ACL either", %{a: a} do
      conn = delete(a.conn, "/api/v1/map_access_lists/#{a.map_acl.id}")

      assert conn.status in [403, 404],
             "map keys are read-only on bindings: unbinding is self-escalation"

      assert binding_exists?(a.map.id, a.acl.id)
    end

    test "cannot repoint an existing binding at another tenant's ACL", %{a: a, b: b} do
      conn =
        patch(
          a.conn,
          "/api/v1/map_access_lists/#{a.map_acl.id}",
          jsonapi(
            "map_access_lists",
            %{"map_id" => a.map.id, "access_list_id" => b.acl.id},
            a.map_acl.id
          )
        )

      assert conn.status in [403, 404], "expected refusal, got #{conn.status}: #{conn.resp_body}"
      refute binding_exists?(a.map.id, b.acl.id)
    end

    test "GET /map_access_lists does not leak another tenant's binding", %{a: a, b: b} do
      assert_index_isolated(
        a.conn,
        "/api/v1/map_access_lists",
        [a.map_acl.id],
        [b.map_acl.id]
      )
    end

    test "the by_acl route cannot be used to reach another tenant's binding", %{a: a, b: b} do
      conn = get(a.conn, "/api/v1/map_access_lists/by_acl/#{b.acl.id}")

      case conn.status do
        200 ->
          ids = json_response(conn, 200)["data"] |> Enum.map(& &1["id"])
          refute b.map_acl.id in ids, "by_acl leaked tenant B's binding"

        status ->
          assert status in [403, 404], "unexpected status #{status}"
      end
    end
  end

  describe "map writes cannot be used to reach another tenant's ACL" do
    test "cannot attach a foreign ACL through PATCH /maps/:id", %{a: a, b: b} do
      patch(
        a.conn,
        "/api/v1/maps/#{a.map.id}",
        jsonapi("maps", %{"acls" => [b.acl.id]}, a.map.id)
      )

      refute binding_exists?(a.map.id, b.acl.id),
             "the JSON:API-routed map update must not manage the acls relationship"

      assert_index_isolated(a.conn, "/api/v1/access_lists", [a.acl.id], [b.acl.id])
    end

    test "the policy refuses any write to another tenant's map", %{a: a, b: b} do
      original_name = reload!(WandererApp.Api.Map, b.map.id).name

      conn =
        patch(
          a.conn,
          "/api/v1/maps/#{b.map.id}",
          jsonapi("maps", %{"name" => "hacked", "slug" => "hacked-slug"}, b.map.id)
        )

      assert conn.status in [403, 404],
             "a valid-shaped write to tenant B's map must be refused by policy, got #{conn.status}: #{conn.resp_body}"

      assert reload!(WandererApp.Api.Map, b.map.id).name == original_name
    end

    test "owner_id is rejected outright by the routed map update action", %{a: a, b: b} do
      original_owner = reload!(WandererApp.Api.Map, b.map.id).owner_id

      conn =
        patch(
          a.conn,
          "/api/v1/maps/#{b.map.id}",
          jsonapi("maps", %{"owner_id" => a.character.id}, b.map.id)
        )

      assert conn.status in [400, 403, 404, 422], "expected refusal, got #{conn.status}"
      assert reload!(WandererApp.Api.Map, b.map.id).owner_id == original_owner
    end

    test "cannot read another tenant's map by slug", %{a: a, b: b} do
      conn = get(a.conn, "/api/v1/maps/#{b.map.slug}")
      assert conn.status in [403, 404], "expected refusal, got #{conn.status}"
    end

    test "cannot reach another tenant's ACLs through ?include=acls", %{a: a, b: b} do
      conn = get(a.conn, "/api/v1/maps/#{b.map.slug}?include=acls")

      case conn.status do
        200 ->
          body = conn.resp_body
          refute body =~ b.acl.id, "include=acls leaked tenant B's ACL"

        status ->
          assert status in [403, 404], "unexpected status #{status}"
      end
    end
  end

  defp member_count(acl_id) do
    AccessListMember
    |> Ash.Query.filter(access_list_id == ^acl_id)
    |> Ash.count!(authorize?: false)
  end

  defp binding_exists?(map_id, acl_id) do
    MapAccessList
    |> Ash.Query.filter(map_id == ^map_id and access_list_id == ^acl_id)
    |> Ash.exists?(authorize?: false)
  end
end
