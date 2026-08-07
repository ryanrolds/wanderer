defmodule WandererAppWeb.ApiSpec do
  @behaviour OpenApiSpex.OpenApi

  alias OpenApiSpex.{OpenApi, Info, Paths, Components, SecurityScheme, Server}
  alias WandererAppWeb.{Endpoint, Router}
  alias WandererAppWeb.Schemas.ApiSchemas

  @impl OpenApiSpex.OpenApi
  def spec do
    %OpenApi{
      info: %Info{
        title: "WandererApp API",
        version: "1.0.0",
        description: "API documentation for WandererApp"
      },
      servers: [
        Server.from_endpoint(Endpoint)
      ],
      paths: Paths.from_router(Router),
      components: %Components{
        securitySchemes: %{
          "mapApiKey" => %SecurityScheme{
            type: "http",
            scheme: "bearer",
            description:
              "Per-map API key, scoped to the single map it belongs to. Not a JWT: " <>
                "it is the map's `public_api_key`, sent as a bearer token."
          },
          "aclApiKey" => %SecurityScheme{
            type: "http",
            scheme: "bearer",
            description:
              "Per-ACL API key, accepted only by the legacy `/api/acls/*` routes. " <>
                "Scoped to the single access list it belongs to. ACLs have no key " <>
                "until one is generated from the access-list edit screen; until then " <>
                "these routes answer 401."
          }
        },
        schemas: %{
          "ErrorResponse" => ApiSchemas.error_response()
        }
      },
      security: [%{"mapApiKey" => []}, %{"aclApiKey" => []}]
    }
  end
end
