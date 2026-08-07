defmodule WandererApp.Api.Preparations.FilterAclsByRoles do
  @moduledoc """
  Scopes the `:available` read to ACLs the actor owns or holds an
  admin/manager role on.

  Kept alongside `WandererApp.Api.Checks.UserAclScope`, which expresses the same
  rule as a policy for the JSON:API surface. The two must stay in agreement:
  `WandererApp.Acls.get_available_acls/1` passes an actor, so it is now
  authorized *and* prepared, and a preparation stricter than the policy would
  silently shrink what the ACL LiveViews show.
  """

  use Ash.Resource.Preparation

  require Ash.Query

  alias WandererApp.Api.ActorHelpers

  # Fails closed: every caller passes an actor, and returning every ACL in the
  # deployment is never what an action named "available" should mean.
  def prepare(query, _params, %{actor: nil}) do
    query
    |> Ash.Query.filter(false)
    |> Ash.Query.load([:owner, :members])
  end

  def prepare(query, _params, %{actor: actor}) do
    query
    |> filter_membership(actor)
    |> Ash.Query.load([:owner, :members])
  end

  defp filter_membership(query, actor) do
    # Via ActorHelpers because `actor.characters` raises on an ActorWithMap.
    {character_ids, character_eve_ids, _corp_ids, _alliance_ids} =
      ActorHelpers.character_identity(actor)

    # exists/2, not a flat conjunction: the flat form matches the character on
    # one member row and the role on another, so a :viewer alongside an
    # unrelated :admin would be granted access.
    Ash.Query.filter(
      query,
      owner_id in ^character_ids or
        exists(members, eve_character_id in ^character_eve_ids and role in [:admin, :manager])
    )
  end
end
