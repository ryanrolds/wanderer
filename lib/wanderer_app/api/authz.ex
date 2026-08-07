defmodule WandererApp.Api.Authz do
  @moduledoc """
  Imperative authorization helpers for create-time policy checks, where there is
  no existing record for a filter expression to match against.

  Every query here runs with `authorize?: false` on purpose: these functions
  *are* the authorization decision and must not recurse into the policies that
  call them.
  """

  require Ash.Query

  alias WandererApp.Api.AccessList
  alias WandererApp.Api.ActorHelpers
  alias WandererApp.Api.MapAccessList

  @doc """
  May the actor administer this ACL - read it and write its members?

  A bearer map API key may administer exactly the ACLs already bound to its own
  map. It deliberately cannot administer an unbound ACL: that is what stops
  "bind a victim ACL to my map, then read it".
  """
  @spec can_manage_acl?(term(), String.t() | nil) :: boolean()
  def can_manage_acl?(_actor, nil), do: false

  def can_manage_acl?(actor, acl_id) do
    case ActorHelpers.principal(actor) do
      {:map_key, _user, map} -> acl_bound_to_map?(acl_id, map.id)
      {:user, _user} -> acl_owner_or_admin?(actor, acl_id)
      {:character, _character} -> acl_owner_or_admin?(actor, acl_id)
      _ -> false
    end
  end

  @doc """
  May the actor administer this map - attach ACLs, change settings?

  Note the asymmetry for map keys: a map key may manage *its own* map only. It
  never inherits its owning user's other maps. That is the point of
  `WandererApp.Api.ActorWithMap`.
  """
  @spec can_manage_map?(term(), String.t() | nil) :: boolean()
  def can_manage_map?(_actor, nil), do: false

  def can_manage_map?(actor, map_id) do
    case ActorHelpers.principal(actor) do
      {:map_key, _user, map} ->
        map.id == map_id

      p when p in [:system, :unknown] ->
        false

      _ ->
        {ids, eve_ids, _corp_ids, _alliance_ids} = ActorHelpers.character_identity(actor)

        WandererApp.Api.Map
        |> Ash.Query.filter(
          id == ^map_id and
            (owner_id in ^ids or
               exists(acls.members, eve_character_id in ^eve_ids and role == :admin))
        )
        |> Ash.exists?(authorize?: false)
    end
  end

  defp acl_bound_to_map?(acl_id, map_id) do
    MapAccessList
    |> Ash.Query.filter(access_list_id == ^acl_id and map_id == ^map_id)
    |> Ash.exists?(authorize?: false)
  end

  defp acl_owner_or_admin?(actor, acl_id) do
    {ids, eve_ids, _corp_ids, _alliance_ids} = ActorHelpers.character_identity(actor)

    AccessList
    |> Ash.Query.filter(
      id == ^acl_id and
        (owner_id in ^ids or
           exists(members, eve_character_id in ^eve_ids and role == :admin))
    )
    |> Ash.exists?(authorize?: false)
  end
end
