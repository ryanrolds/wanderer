defmodule WandererApp.Api do
  @moduledoc false

  use Ash.Domain,
    extensions: [AshJsonApi.Domain]

  json_api do
    prefix "/api/v1"
    log_errors?(true)
  end

  authorization do
    # Internal callers (LiveViews, map-server GenServers, jobs) pass no actor and
    # are trusted; auditing all ~337 of them was not viable.
    #
    # Adding `actor:` to an internal call therefore opts it into policy
    # enforcement -- `:when_requested` keys off key presence, so even
    # `actor: nil` authorizes. See test/unit/api/actor_call_sites_test.exs first.
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
