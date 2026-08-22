defmodule WandererAppWeb.OpenApi do
  @moduledoc """
  Generates OpenAPI spec for v1 JSON:API endpoints using AshJsonApi.
  """

  alias OpenApiSpex.{OpenApi, Info, Server, Components}

  def spec do
    %OpenApi{
      info: %Info{
        title: "WandererApp v1 JSON:API",
        version: "1.0.0",
        description: """
        JSON:API compliant endpoints for WandererApp.

        ## Features
        - Filtering: Use `filter[attribute]=value` parameters
        - Sorting: Use `sort=attribute` or `sort=-attribute` for descending
        - Pagination: Use `page[limit]=n` and `page[offset]=n`
        - Relationships: Include related resources with `include=relationship`

        ## Authentication and scope

        Either a per-map API key as a bearer token:
        ```
        Authorization: Bearer YOUR_MAP_API_KEY
        ```
        or a browser session cookie from EVE SSO login.

        A map API key is **scoped to its own map**. It is not an
        administrative credential: it cannot read or write another map's
        data, cannot list access lists belonging to other maps, cannot
        create maps or access lists, and cannot change which access lists
        are bound to a map. See the `mapApiKey` security scheme for the
        exact boundary.

        Note that ACL API keys are **not** accepted here. They authenticate
        only the legacy `/api/acls/*` routes documented in the separate
        legacy spec.
        """
      },
      servers: [
        Server.from_endpoint(WandererAppWeb.Endpoint)
      ],
      paths:
        merge_custom_paths(AshJsonApi.OpenApi.paths([WandererApp.Api], [WandererApp.Api], %{})),
      tags: AshJsonApi.OpenApi.tags([WandererApp.Api]),
      components: %Components{
        responses: AshJsonApi.OpenApi.responses(),
        schemas: AshJsonApi.OpenApi.schemas([WandererApp.Api]),
        securitySchemes: %{
          "mapApiKey" => %{
            "type" => "http",
            "scheme" => "bearer",
            "description" => """
            Per-map API key, from Map settings -> "Public API key".

            Scoped to the single map it belongs to. It can read and write that
            map's systems, connections, signatures and structures, and can read
            and manage the *contents* (members, roles, name) of the access lists
            already bound to that map.

            It cannot: read or modify any other map's data; create maps or
            access lists; or change which access lists are bound to a map.
            Binding requires authority over both the map and the target ACL, so
            it is a session-user operation.
            """
          },
          "sessionCookie" => %{
            "type" => "apiKey",
            "in" => "cookie",
            "name" => "_wanderer_app_key",
            "description" => """
            Browser session cookie, set after EVE SSO login.

            Scoped by access-list membership across every map the user can
            reach, using the role model in `WandererApp.Permissions`
            (viewer < member < manager < admin).
            """
          }
        }
      },
      # A top-level list of single-key objects means OR in OpenAPI 3: either
      # credential is sufficient. That matches CheckJsonApiAuth, which accepts a
      # bearer map key or falls back to the session.
      security: [%{"mapApiKey" => []}, %{"sessionCookie" => []}]
    }
  end

  defp merge_custom_paths(ash_paths) do
    custom_paths = %{
      "/maps/{map_id}/systems_and_connections" => %{
        "get" => %{
          "tags" => ["maps"],
          "summary" => "Get Map Systems and Connections",
          "description" => "Retrieve both systems and connections for a map in a single response",
          "operationId" => "getMapSystemsAndConnections",
          "parameters" => [
            %{
              "name" => "map_id",
              "in" => "path",
              "description" => "Map ID",
              "required" => true,
              "schema" => %{"type" => "string"}
            }
          ],
          "responses" => %{
            "200" => %{
              "description" => "Combined systems and connections data",
              "content" => %{
                "application/json" => %{
                  "schema" => %{
                    "type" => "object",
                    "properties" => %{
                      "systems" => %{
                        "type" => "array",
                        "items" => %{
                          "$ref" => "#/components/schemas/MapSystem"
                        }
                      },
                      "connections" => %{
                        "type" => "array",
                        "items" => %{
                          "$ref" => "#/components/schemas/MapConnection"
                        }
                      }
                    }
                  }
                }
              }
            },
            "404" => %{
              "description" => "Map not found",
              "content" => %{
                "application/json" => %{
                  "schema" => %{
                    "type" => "object",
                    "properties" => %{
                      "error" => %{"type" => "string"}
                    }
                  }
                }
              }
            },
            "401" => %{
              "description" => "Unauthorized",
              "content" => %{
                "application/json" => %{
                  "schema" => %{
                    "type" => "object",
                    "properties" => %{
                      "error" => %{"type" => "string"}
                    }
                  }
                }
              }
            }
          },
          "security" => [%{"mapApiKey" => []}, %{"sessionCookie" => []}]
        }
      }
    }

    Map.merge(ash_paths, custom_paths)
  end
end
