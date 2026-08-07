defmodule WandererApp.Api.Checks.UserAclScope do
  @moduledoc """
  Filter check: a session user may reach ACLs they own, or hold a qualifying
  role on.

  Deliberately mirrors `WandererApp.Api.Preparations.FilterAclsByRoles` so that
  `WandererApp.Acls.get_available_acls/1` returns the same set with
  authorization on as it did with it off.

  One deliberate difference: the membership test is written as `exists/2` rather
  than the preparation's `members.eve_character_id in ^ids and members.role in
  ^roles`. The latter can match the character on one joined row and the role on
  a *different* row. `exists/2` requires both on the same row.

  Options:

    * `:via`   - `[]` (on AccessList) or `[:access_list]` (on AccessListMember)
    * `:roles` - roles that qualify; `[:admin, :manager]` for read,
                 `[:admin]` for write

  Fails closed for map keys and for absent actors.
  """

  use Ash.Policy.FilterCheck

  require Ash.Expr

  alias WandererApp.Api.ActorHelpers

  @impl true
  def describe(opts),
    do: "actor owns the access list or holds #{inspect(Keyword.fetch!(opts, :roles))} on it"

  @impl true
  def filter(actor, _context, opts) do
    roles = Keyword.fetch!(opts, :roles)

    case ActorHelpers.principal(actor) do
      {:map_key, _user, _map} ->
        Ash.Expr.expr(false)

      p when p in [:system, :unknown] ->
        Ash.Expr.expr(false)

      _ ->
        {ids, eve_ids, _corp_ids, _alliance_ids} = ActorHelpers.character_identity(actor)

        case Keyword.get(opts, :via, []) do
          [] ->
            Ash.Expr.expr(
              owner_id in ^ids or
                exists(members, eve_character_id in ^eve_ids and role in ^roles)
            )

          [:access_list] ->
            Ash.Expr.expr(
              access_list.owner_id in ^ids or
                exists(access_list.members, eve_character_id in ^eve_ids and role in ^roles)
            )
        end
    end
  end
end
