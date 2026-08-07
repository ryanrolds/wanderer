defmodule WandererAppWeb.ApiCase do
  @moduledoc """
  This module defines the test case to be used by
  tests that require testing API endpoints with OpenAPI validation.

  Such tests rely on `Phoenix.ConnTest` and include helpers for:
  - OpenAPI schema validation
  - API authentication setup
  - Common response assertions
  - Test data factories
  """

  use ExUnit.CaseTemplate

  # `get/2` expands to `dispatch(conn, @endpoint, ...)`, and @endpoint only
  # exists inside the `using` block -- so helpers here dispatch explicitly.
  @endpoint_module WandererAppWeb.Endpoint

  using do
    quote do
      # The default endpoint for testing
      @endpoint WandererAppWeb.Endpoint

      use WandererAppWeb, :verified_routes

      # Import conveniences for testing with connections
      import Plug.Conn
      import Phoenix.ConnTest
      import WandererAppWeb.ApiCase

      # Import OpenAPI helpers
      import WandererAppWeb.OpenAPIHelpers

      # Import factories
      import WandererAppWeb.Factory
    end
  end

  setup tags do
    # Determine if this is an integration test based on the test file path
    # Integration tests are in test/integration/ directory
    integration_test? = tags[:file] && String.contains?(tags[:file], "/integration/")

    # Use shared mode for async integration tests
    if integration_test? do
      IO.puts("DEBUG: Integration test detected: #{tags[:file]}")
      WandererAppWeb.IntegrationConnCase.setup_sandbox(tags)
    else
      IO.puts("DEBUG: Unit test detected: #{tags[:file]}")
      WandererApp.DataCase.setup_sandbox(tags)
    end

    # Set up mocks for this test process
    # Use global mode for integration tests so mocks work in spawned processes
    mock_mode = if integration_test?, do: :global, else: :private
    WandererApp.Test.Mocks.setup_test_mocks(mode: mock_mode)

    # Set up integration test environment if needed
    if integration_test? do
      WandererApp.Test.IntegrationConfig.setup_integration_environment()
      WandererApp.Test.IntegrationConfig.setup_test_reliability_configs()

      on_exit(fn ->
        WandererApp.Test.IntegrationConfig.cleanup_integration_environment()
      end)
    end

    # Handle skip_if_api_disabled tag
    # Note: ExUnit skip functionality isn't available in setup, so we'll return :skip
    if Map.has_key?(tags, :skip_if_api_disabled) and WandererApp.Env.character_api_disabled?() do
      {:skip, "Character API is disabled"}
    else
      {:ok, conn: Phoenix.ConnTest.build_conn()}
    end
  end

  @doc """
  Helper for creating API authentication headers
  """
  def put_api_key(conn, api_key) do
    conn
    |> Plug.Conn.put_req_header("authorization", "Bearer #{api_key}")
    |> Plug.Conn.put_req_header("content-type", "application/json")
  end

  @doc """
  Helper for creating map-specific API authentication
  """
  def authenticate_map_api(conn, map) do
    # Use the map's actual public_api_key if available
    api_key = map.public_api_key || "test_api_key_#{map.id}"
    put_api_key(conn, api_key)
  end

  @doc """
  Helper for asserting successful JSON responses with optional schema validation
  """
  def assert_json_response(conn, status, schema_name \\ nil) do
    response = Phoenix.ConnTest.json_response(conn, status)

    if schema_name do
      WandererAppWeb.OpenAPIHelpers.assert_schema(
        response,
        schema_name,
        WandererAppWeb.OpenAPIHelpers.api_spec()
      )
    end

    response
  end

  @doc """
  Helper for asserting error responses
  """
  def assert_error_response(conn, status, expected_error \\ nil) do
    response = Phoenix.ConnTest.json_response(conn, status)
    assert %{"error" => error_msg} = response

    if expected_error do
      assert error_msg =~ expected_error
    end

    response
  end

  @doc """
  Setup callback for tests that need map authentication.
  Creates a test map and authenticates the connection.
  """
  def setup_map_authentication(%{conn: conn}) do
    # Create a test map
    map = WandererAppWeb.Factory.insert(:map, %{slug: "test-map-#{System.unique_integer()}"})

    # Create an active subscription for the map if subscriptions are enabled
    if WandererApp.Env.map_subscriptions_enabled?() do
      create_active_subscription_for_map(map.id)
    end

    # Ensure the map server is started
    # Note: Map servers are granted database/mock access via the MapPoolSupervisor in DataCase
    WandererApp.TestHelpers.ensure_map_server_started(map.id)

    # Grant database/mock access to MapEventRelay if running
    if pid = Process.whereis(WandererApp.ExternalEvents.MapEventRelay) do
      WandererApp.DataCase.allow_database_access(pid)
      WandererApp.Test.MockOwnership.allow_mocks_for_process(pid)
    end

    # Authenticate the connection with the map's actual public_api_key
    authenticated_conn = put_api_key(conn, map.public_api_key)
    {:ok, conn: authenticated_conn, map: map}
  end

  @doc """
  Setup callback for tests that need map authentication without starting map servers.
  Creates a test map and authenticates the connection, but doesn't start the map server.
  Use this for integration tests that don't need the full map server infrastructure.
  """
  def setup_map_authentication_without_server(%{conn: conn}) do
    # Create a test map
    map = WandererAppWeb.Factory.insert(:map, %{slug: "test-map-#{System.unique_integer()}"})
    # Authenticate the connection with the map's actual public_api_key
    authenticated_conn = put_api_key(conn, map.public_api_key)
    {:ok, conn: authenticated_conn, map: map}
  end

  @doc """
  Helper for creating authenticated connection for JSON:API V1 endpoints.
  Sets both authorization and content-type headers for JSON:API format.
  """
  def create_authenticated_conn(conn, map) do
    conn
    |> Plug.Conn.put_req_header("authorization", "Bearer #{map.public_api_key}")
    |> Plug.Conn.put_req_header("content-type", "application/vnd.api+json")
  end

  @doc """
  Builds two fully independent tenants for cross-tenant authorization tests.

  Each tenant gets its own user, character, map (with a distinct
  `public_api_key`), access list bound to that map through a
  `map_access_lists_v1` row, and one ACL member. Returns
  `%{a: tenant, b: tenant}` where each tenant is a map of
  `%{user:, character:, map:, acl:, acl_member:, map_acl:, conn:}` and `conn` is
  already authenticated with that tenant's map API key.

  Deliberately does not start a map server -- none of the authorization tests
  need one, and starting two doubles the flake surface.
  """
  def setup_two_tenants(%{conn: conn}) do
    {:ok, a: build_tenant(conn, "a"), b: build_tenant(conn, "b")}
  end

  defp build_tenant(conn, label) do
    n = System.unique_integer([:positive])

    user = WandererAppWeb.Factory.insert(:user)
    character = WandererAppWeb.Factory.insert(:character, %{user_id: user.id})

    map =
      WandererAppWeb.Factory.insert(:map, %{
        owner_id: character.id,
        slug: "tenant-#{label}-#{n}"
      })

    acl =
      WandererAppWeb.Factory.insert(:access_list, %{
        owner_id: character.id,
        name: "acl-#{label}-#{n}"
      })

    acl_member =
      WandererAppWeb.Factory.insert(:access_list_member, %{
        access_list_id: acl.id,
        name: "member-#{label}-#{n}",
        eve_character_id: "#{9_000_000 + n}",
        role: :admin
      })

    map_acl =
      WandererAppWeb.Factory.insert(:map_access_list, %{
        map_id: map.id,
        access_list_id: acl.id
      })

    %{
      user: user,
      character: character,
      map: map,
      acl: acl,
      acl_member: acl_member,
      map_acl: map_acl,
      conn: create_authenticated_conn(conn, map)
    }
  end

  @doc """
  Asserts that `GET path` returns every id in `own_ids` and none in
  `foreign_ids`.

  Fails loudly on a non-200 so that a policy compile error or a
  deny-everything policy cannot masquerade as "no data leaked".
  """
  def assert_index_isolated(conn, path, own_ids, foreign_ids) do
    conn = Phoenix.ConnTest.dispatch(conn, @endpoint_module, :get, path)

    unless conn.status == 200 do
      raise ExUnit.AssertionError,
        message: "expected 200 from #{path}, got #{conn.status}: #{conn.resp_body}"
    end

    ids = Phoenix.ConnTest.json_response(conn, 200)["data"] |> Enum.map(& &1["id"])

    for id <- foreign_ids do
      ExUnit.Assertions.refute(id in ids, "#{path} leaked foreign record #{id}")
    end

    for id <- own_ids do
      ExUnit.Assertions.assert(id in ids, "#{path} hid own record #{id}")
    end

    ids
  end

  @doc """
  Asserts a cross-tenant `GET path/foreign_id` is not readable.

  Accepts 403 or 404: Ash filter-check policies make an unauthorized record
  indistinguishable from a missing one, which is the desired behaviour.
  """
  def assert_show_denied(conn, path, foreign_id) do
    conn = Phoenix.ConnTest.dispatch(conn, @endpoint_module, :get, "#{path}/#{foreign_id}")

    ExUnit.Assertions.assert(
      conn.status in [403, 404],
      "expected 403/404 for #{path}/#{foreign_id}, got #{conn.status}: #{conn.resp_body}"
    )

    conn
  end

  # Creates an active subscription for a map to bypass subscription checks in tests.
  defp create_active_subscription_for_map(map_id) do
    # Create a subscription with a non-alpha plan (status defaults to :active)
    {:ok, _subscription} =
      Ash.create(WandererApp.Api.MapSubscription, %{
        map_id: map_id,
        plan: :omega,
        characters_limit: 100,
        hubs_limit: 10,
        auto_renew?: true,
        active_till: DateTime.utc_now() |> DateTime.add(30, :day)
      })
  end
end
