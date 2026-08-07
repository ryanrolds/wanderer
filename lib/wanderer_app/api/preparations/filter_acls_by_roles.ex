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

  # Fails closed. Every caller of :available passes an actor
  # (WandererApp.Acls.get_available_acls/1); the actor-less arity was removed
  # because returning every ACL in the deployment is never what a caller wants
  # from an action named "available".
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
    # Via ActorHelpers rather than `actor.characters`: the actor may be a bare
    # User, a bare Character, or an ActorWithMap, and the last has no
    # :characters key at all.
    {character_ids, character_eve_ids, _corp_ids, _alliance_ids} =
      ActorHelpers.character_identity(actor)

    # `exists/2` rather than `members.eve_character_id in ^ids and members.role
    # in [...]`: the flat form can match the character on one joined member row
    # and the role on a *different* row, granting access to someone who is
    # merely a :viewer alongside an unrelated :admin. exists/2 requires both
    # conditions on the same row.
    Ash.Query.filter(
      query,
      owner_id in ^character_ids or
        exists(members, eve_character_id in ^character_eve_ids and role in [:admin, :manager])
    )
  end
end
