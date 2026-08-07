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

  # Deliberately fails OPEN over live maps, unlike the ACL equivalent.
  #
  # `WandererApp.Maps.get_available_maps/0` relies on this branch to build the
  # deployment-wide kill-subscription index (kills/subscription/*), which
  # genuinely needs every live map and has no user to scope by. Note that
  # `authorize?: false` would NOT restore this behaviour if the branch were
  # changed -- preparations run regardless of authorization -- so the actor-less
  # callers would break outright.
  #
  # This is not a hole in the HTTP surface: :available is not routed via
  # JSON:API, and the reachable read actions are policy-gated.
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
    # Via ActorHelpers rather than `actor.characters`: the actor may be a bare
    # User, a bare Character, or an ActorWithMap, and the last has no
    # :characters key at all.
    {character_ids, character_eve_ids, character_corporation_ids, character_alliance_ids} =
      ActorHelpers.character_identity(actor)

    # `exists/2` per clause rather than a flat conjunction over the joined rows;
    # see the note in FilterAclsByRoles for why the flat form can match two
    # conditions against two different member rows.
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
