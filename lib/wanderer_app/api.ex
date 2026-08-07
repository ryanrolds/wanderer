defmodule WandererApp.Api do
  @moduledoc false

  use Ash.Domain,
    extensions: [AshJsonApi.Domain]

  json_api do
    prefix "/api/v1"
    log_errors?(true)
  end

  authorization do
    # HTTP requests carry an actor (CheckJsonApiAuth -> Ash.PlugHelpers.set_actor/2)
    # and are authorized. Internal calls from LiveViews, map-server GenServers,
    # repositories and background jobs pass no actor and are trusted.
    #
    # Note: AshJsonApi additionally passes an explicit `authorize?: true` derived
    # from `AshJsonApi.Domain.Info.authorize?/1` (which defaults to true), so the
    # /api/v1 surface is policed regardless of this setting.
    #
    # Consequence: adding `actor:` to an internal Ash call opts that call into
    # policy enforcement -- `:when_requested` keys off `Keyword.has_key?(opts, :actor)`,
    # so even `actor: nil` authorizes. See test/unit/api/actor_call_sites_test.exs
    # before adding one.
    authorize :when_requested
    require_actor? false
  end

  resources do
    resource WandererApp.Api.AccessList
    resource WandererApp.Api.AccessListMember
    resource WandererApp.Api.Character
    resource WandererApp.Api.Map
    resource WandererApp.Api.MapAccessList
    resource WandererApp.Api.MapSolarSystem
    resource WandererApp.Api.MapSolarSystemJumps
    resource WandererApp.Api.MapChainPassages
    resource WandererApp.Api.MapConnection
    resource WandererApp.Api.MapState
    resource WandererApp.Api.MapSystem
    resource WandererApp.Api.MapSystemComment
    resource WandererApp.Api.MapSystemSignature
    resource WandererApp.Api.MapSystemStructure
    resource WandererApp.Api.MapCharacterSettings
    resource WandererApp.Api.MapSubscription
    resource WandererApp.Api.MapTransaction
    resource WandererApp.Api.MapUserSettings
    resource WandererApp.Api.MapDefaultSettings
    resource WandererApp.Api.User
    resource WandererApp.Api.ShipTypeInfo
    resource WandererApp.Api.UserActivity
    resource WandererApp.Api.UserTransaction
    resource WandererApp.Api.CorpWalletTransaction
    resource WandererApp.Api.License
    resource WandererApp.Api.MapPing
    resource WandererApp.Api.MapInvite
    resource WandererApp.Api.MapWebhookSubscription
  end
end
