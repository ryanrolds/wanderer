defmodule WandererApp.Api.Preparations.FilterMapsByRoles do
  @moduledoc """
  Scopes the `:available` read to maps the actor owns or can reach through ACL
  membership, by character, corporation or alliance.

  Kept alongside `WandererApp.Api.Checks.UserMapScope` at `level: :any`, which
  expresses the same rule as a policy for the JSON:API surface. The two must
  stay in agreement: `WandererApp.Maps.get_available_maps/1` passes an actor, so
  it is now authorized *and* prepared, and a preparation stricter than the
  policy would silently shrink the map list in the UI.
  """

  use Ash.Resource.Preparation

  require Ash.Query

  alias WandererApp.Api.ActorHelpers

  # Fails open over live maps, unlike the ACL equivalent: the kill-subscription
  # index (kills/subscription/*) needs every live map and has no user to scope
  # by. Failing it closed would break those callers outright -- `authorize?:
  # false` would not help, since preparations run regardless of authorization.
  #
  # Not an HTTP hole: :available is unrouted and the reachable reads are policed.
  def prepare(query, _params, %{actor: nil}) do
    query
    |> Ash.Query.filter(expr(deleted == false))
    |> Ash.Query.load([:owner, :acls])
  end

  def prepare(query, _params, %{actor: actor}) do
    query
    |> Ash.Query.filter(expr(deleted == false))
    |> filter_membership(actor)
    |> Ash.Query.load([:owner, :acls])
  end

  defp filter_membership(query, actor) do
    # Via ActorHelpers because `actor.characters` raises on an ActorWithMap.
    {character_ids, character_eve_ids, character_corporation_ids, character_alliance_ids} =
      ActorHelpers.character_identity(actor)

    # exists/2 per clause -- see FilterAclsByRoles for why a flat conjunction
    # can match two conditions against two different member rows.
    query
    |> Ash.Query.filter(
      owner_id in ^character_ids or
        exists(acls, owner_id in ^character_ids) or
        exists(acls.members, eve_character_id in ^character_eve_ids) or
        exists(acls.members, eve_corporation_id in ^character_corporation_ids) or
        exists(acls.members, eve_alliance_id in ^character_alliance_ids)
    )
  end
end
