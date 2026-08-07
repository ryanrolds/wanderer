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
    # A map API key sees the ACLs bound to its own map (legacy /api/map/acls
    # semantics). A session user sees ACLs they own or admin/manage.
    policy action_type(:read) do
      authorize_if {Checks.ActorMapScope, via: [:acl]}
      authorize_if {Checks.UserAclScope, roles: [:admin, :manager]}
    end

    # Minting an ACL is a user-level act. A map API key must never create one:
    # a new ACL is bound to no map, so no map-scoped read policy could govern it.
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
      # :api_create rather than :new -- withholds :api_key and constrains
      # :owner_id to the caller's own characters.
      post(:api_create)
      # :api_update rather than :update -- withholds :owner_id and :api_key.
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

    # Broad create, used by the ACL "new" LiveView form
    # (access_lists_live.ex:69, which can also set :api_key via the
    # "generate-api-key" event). Deliberately NOT routed via JSON:API --
    # see :api_create below.
    create :new do
      # Added :api_key to the accepted attributes
      accept [:name, :description, :owner_id, :api_key]
      primary?(true)
    end

    # The JSON:API-routed create.
    #
    # :api_key is withheld -- keys are a credential for the legacy /api/acls/*
    # surface (Plugs.CheckAclApiKey authenticates against acl.api_key) and must
    # be server-generated via :update_api_key, never chosen by a client.
    #
    # :owner_id is still accepted, because an access list is owned by a
    # Character and a user may have several, so it cannot be derived from the
    # actor. It is constrained to the caller's own characters instead.
    create :api_create do
      accept [:name, :description, :owner_id]

      validate WandererApp.Api.Validations.OwnerIsActorCharacter
    end

    # Broad update, used by the ACL edit LiveView form (access_lists_live.ex:87,
    # which also sets :api_key via the "generate-api-key" event). Deliberately
    # NOT routed via JSON:API -- see :api_update below.
    update :update do
      accept [:name, :description, :owner_id, :api_key]
      primary?(true)
      require_atomic? false
    end

    # The JSON:API-routed update. :owner_id and :api_key are withheld: a map API
    # key passes the update policy for an ACL bound to its own map, so leaving
    # either writable would allow ACL takeover, or injection of a known
    # credential into the legacy /api/acls/* surface (Plugs.CheckAclApiKey
    # authenticates against acl.api_key).
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

    # Policy traversal only: lets ActorMapScope reach a map key's map through
    # the join table. public? false keeps it out of the JSON:API schema.
    has_many :map_access_lists, WandererApp.Api.MapAccessList do
      destination_attribute :access_list_id
      public? false
    end
  end
end
