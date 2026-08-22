defmodule WandererApp.Api.MapAccessList do
  @moduledoc false

  use Ash.Resource,
    domain: WandererApp.Api,
    data_layer: AshPostgres.DataLayer,
    authorizers: [Ash.Policy.Authorizer],
    extensions: [AshJsonApi.Resource]

  alias WandererApp.Api.Checks

  postgres do
    repo(WandererApp.Repo)
    table("map_access_lists_v1")
  end

  policies do
    policy action_type(:read) do
      authorize_if {Checks.ActorMapScope, via: []}
      authorize_if {Checks.UserMapScope, via: [:map], level: :edit}
    end

    # Binding grants the map's principals read access to the ACL, so requiring
    # only map-side authority would let a key attach any ACL and then read it --
    # the original vulnerability via another door. Both sides required.
    policy action_type(:create) do
      forbid_unless Checks.CanManageTargetMap
      authorize_if Checks.CanManageTargetAcl
    end

    # ActorMapScope omitted: "unbind the ACL, become unconstrained" is a
    # self-escalation, so map keys are read-only here.
    policy action_type([:update, :destroy]) do
      authorize_if {Checks.UserMapScope, via: [:map], level: :edit}
    end
  end

  json_api do
    type "map_access_lists"

    # Handle composite primary key
    primary_key do
      keys([:id])
    end

    includes([
      :map,
      :access_list
    ])

    # Enable automatic filtering and sorting
    derive_filter?(true)
    derive_sort?(true)

    routes do
      base("/map_access_lists")

      get(:read)
      index :read
      post(:create)
      patch(:update)
      delete(:destroy)

      # Custom routes for specific queries
      get(:read_by_map, route: "/by_map/:map_id")
      get(:read_by_acl, route: "/by_acl/:acl_id")
    end
  end

  code_interface do
    define(:create, action: :create)

    define(:read_by_map,
      action: :read_by_map
    )

    define(:read_by_acl,
      action: :read_by_acl
    )
  end

  actions do
    default_accept [
      :map_id,
      :access_list_id
    ]

    defaults [:create, :read, :destroy]

    update :update do
      require_atomic? false
    end

    read :read_by_map do
      argument(:map_id, :string, allow_nil?: false)
      filter(expr(map_id == ^arg(:map_id)))
    end

    read :read_by_acl do
      argument(:acl_id, :string, allow_nil?: false)
      filter(expr(access_list_id == ^arg(:acl_id)))
    end
  end

  attributes do
    uuid_primary_key :id

    create_timestamp(:inserted_at)
    update_timestamp(:updated_at)
  end

  relationships do
    belongs_to :map, WandererApp.Api.Map, primary_key?: true, allow_nil?: false, public?: true

    belongs_to :access_list, WandererApp.Api.AccessList,
      primary_key?: true,
      allow_nil?: false,
      public?: true
  end

  postgres do
    references do
      reference :map, on_delete: :delete
      reference :access_list, on_delete: :delete
    end
  end

  identities do
    identity :unique_map_acl, [:map_id, :access_list_id] do
      pre_check?(false)
    end
  end
end
