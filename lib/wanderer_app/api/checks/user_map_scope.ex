defmodule WandererApp.Api.Checks.UserMapScope do
  @moduledoc """
  Filter check: a session user's access to a map.

  Mirrors `WandererApp.Api.Preparations.FilterMapsByRoles` at `:any`, and
  `WandererApp.Maps.can_edit?/2` at `:edit`.

  Options:

    * `:level` - `:any` (owner, ACL owner, or any member by character /
      corporation / alliance), `:edit` (owner or ACL `:admin`), or `:own`
      (map owner only)
    * `:via`   - `[]` when the resource *is* the map, `[:map]` when it has a
      `map_id`, `[:system]` when it reaches the map via `system.map`

  `:any` is intentionally no stricter than `FilterMapsByRoles`: it omits the
  `deleted == false` filter, which the `:available` preparation still applies.

  Fails closed for map keys and for absent actors.
  """

  use Ash.Policy.FilterCheck

  require Ash.Expr

  alias WandererApp.Api.ActorHelpers

  @impl true
  def describe(opts), do: "actor has #{Keyword.fetch!(opts, :level)} access to the map"

  @impl true
  def filter(actor, _context, opts) do
    case ActorHelpers.principal(actor) do
      {:map_key, _user, _map} ->
        Ash.Expr.expr(false)

      p when p in [:system, :unknown] ->
        Ash.Expr.expr(false)

      _ ->
        {ids, eve_ids, corp_ids, alliance_ids} = ActorHelpers.character_identity(actor)
        level = Keyword.fetch!(opts, :level)

        case {Keyword.get(opts, :via, []), level} do
          {[], :own} ->
            Ash.Expr.expr(owner_id in ^ids)

          {[], :edit} ->
            Ash.Expr.expr(
              owner_id in ^ids or
                exists(acls.members, eve_character_id in ^eve_ids and role == :admin)
            )

          {[], :any} ->
            Ash.Expr.expr(
              owner_id in ^ids or
                exists(acls, owner_id in ^ids) or
                exists(acls.members, eve_character_id in ^eve_ids) or
                exists(acls.members, eve_corporation_id in ^corp_ids) or
                exists(acls.members, eve_alliance_id in ^alliance_ids)
            )

          {[:map], :own} ->
            Ash.Expr.expr(map.owner_id in ^ids)

          {[:map], :edit} ->
            Ash.Expr.expr(
              map.owner_id in ^ids or
                exists(map.acls.members, eve_character_id in ^eve_ids and role == :admin)
            )

          {[:map], :any} ->
            Ash.Expr.expr(
              map.owner_id in ^ids or
                exists(map.acls, owner_id in ^ids) or
                exists(map.acls.members, eve_character_id in ^eve_ids) or
                exists(map.acls.members, eve_corporation_id in ^corp_ids) or
                exists(map.acls.members, eve_alliance_id in ^alliance_ids)
            )

          {[:system], :own} ->
            Ash.Expr.expr(system.map.owner_id in ^ids)

          {[:system], :edit} ->
            Ash.Expr.expr(
              system.map.owner_id in ^ids or
                exists(system.map.acls.members, eve_character_id in ^eve_ids and role == :admin)
            )

          {[:system], :any} ->
            Ash.Expr.expr(
              system.map.owner_id in ^ids or
                exists(system.map.acls, owner_id in ^ids) or
                exists(system.map.acls.members, eve_character_id in ^eve_ids) or
                exists(system.map.acls.members, eve_corporation_id in ^corp_ids) or
                exists(system.map.acls.members, eve_alliance_id in ^alliance_ids)
            )
        end
    end
  end
end
