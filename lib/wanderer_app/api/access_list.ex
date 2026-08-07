defmodule WandererApp.Api.AccessList do
  @moduledoc false

  use Ash.Resource,
    domain: WandererApp.Api,
    data_layer: AshPostgres.DataLayer,
    authorizers: [Ash.Policy.Authorizer],
    extensions: [AshJsonApi.Resource]

  alias WandererApp.Api.Checks

  postgres do
    repo(WandererApp.Repo)
    table("access_lists_v1")
  end

  policies do
    # Mirrors legacy /api/map/acls semantics for map keys.
    policy action_type(:read) do
      authorize_if {Checks.ActorMapScope, via: [:acl]}
      authorize_if {Checks.UserAclScope, roles: [:admin, :manager]}
    end

    # A new ACL is bound to no map, so no map-scoped policy could govern it
    # afterwards -- hence map keys cannot create.
    policy action_type(:create) do
      forbid_unless Checks.ActorIsNotMapKey
      authorize_if {Checks.CreationPermitted, flag: :acls}
    end

    policy action_type([:update, :destroy]) do
      authorize_if {Checks.ActorMapScope, via: [:acl]}
      authorize_if {Checks.UserAclScope, roles: [:admin]}
    end
  end

  json_api do
    type "access_lists"

    includes([:owner, :members])

    default_fields([
      :name,
      :description
    ])

    derive_filter?(true)
    derive_sort?(true)

    routes do
      base("/access_lists")
      get(:read)
      index :read
      post(:api_create)
      patch(:api_update)
      delete(:destroy)
    end
  end

  code_interface do
    define(:create, action: :create)
    define(:available, action: :available)
    define(:new, action: :new)
    define(:read, action: :read)
    define(:update, action: :update)
    define(:destroy, action: :destroy)

    define(:by_id,
      get_by: [:id],
      action: :read
    )
  end

  actions do
    default_accept [
      :name,
      :description,
      :owner_id
    ]

    defaults [:create, :read, :destroy]

    read :available do
      prepare WandererApp.Api.Preparations.FilterAclsByRoles
    end

    # Unrouted: the ACL "new" LiveView form (access_lists_live.ex:69) needs
    # :owner_id and :api_key, which the API must not accept.
    create :new do
      accept [:name, :description, :owner_id, :api_key]
      primary?(true)
    end

    # api_key authenticates the legacy /api/acls/* surface (CheckAclApiKey), so
    # it must never be client-chosen. owner_id stays accepted only because a
    # user may have several characters; the validation constrains it to theirs.
    create :api_create do
      accept [:name, :description, :owner_id]

      validate WandererApp.Api.Validations.OwnerIsActorCharacter
    end

    # Unrouted: the ACL edit LiveView form (access_lists_live.ex:87) needs
    # :owner_id and :api_key, which the API must not accept.
    update :update do
      accept [:name, :description, :owner_id, :api_key]
      primary?(true)
      require_atomic? false
    end

    # A map key passes the update policy for its own bound ACL, so a writable
    # owner_id would be ACL takeover and a writable api_key would inject a known
    # credential into the legacy /api/acls/* surface.
    update :api_update do
      accept [:name, :description]
      require_atomic? false
    end

    update :assign_owner do
      accept [:owner_id]
      require_atomic? false
    end
  end

  attributes do
    uuid_primary_key :id

    attribute :name, :string do
      allow_nil? false
      public? true
    end

    attribute :description, :string do
      allow_nil? true
      public? true
    end

    # Note: api_key intentionally not public for security
    attribute :api_key, :string do
      allow_nil? true
    end

    create_timestamp(:inserted_at)
    update_timestamp(:updated_at)
  end

  relationships do
    belongs_to :owner, WandererApp.Api.Character do
      attribute_writable? true
      public? true
    end

    has_many :members, WandererApp.Api.AccessListMember do
      public? true
    end

    # Policy traversal only; public? false keeps it out of the JSON:API schema.
    has_many :map_access_lists, WandererApp.Api.MapAccessList do
      destination_attribute :access_list_id
      public? false
    end
  end
end
