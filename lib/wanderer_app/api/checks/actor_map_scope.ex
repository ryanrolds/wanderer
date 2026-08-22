defmodule WandererApp.Api.Checks.ActorMapScope do
  @moduledoc """
  Filter check: the record belongs to the bearer map API key's map.

  Options:

    * `:via` - expression path from this resource to the map.
      * `[]`              - the resource has a `map_id` attribute directly
      * `[:self]`         - the resource *is* the map
      * `[:system]`       - reach the map via `system.map_id`
      * `[:acl]`          - an AccessList, via its `map_access_lists` join rows
      * `[:access_list]`  - an AccessListMember, one hop further

  Fails closed: a non-map-key actor yields `expr(false)`, so this check never
  authorizes on its own. Pair it with a user-scoped `authorize_if`.
  """

  use Ash.Policy.FilterCheck

  require Ash.Expr

  alias WandererApp.Api.ActorHelpers

  @impl true
  def describe(opts) do
    case Keyword.get(opts, :via, []) do
      [] -> "record's map is the actor's API-key map"
      [:self] -> "record is the actor's API-key map"
      via -> "record's #{Enum.join(via, ".")} belongs to the actor's API-key map"
    end
  end

  @impl true
  def filter(actor, _context, opts) do
    case ActorHelpers.actor_map_id(actor) do
      nil ->
        Ash.Expr.expr(false)

      map_id ->
        # Ash filter expressions are macros, so :via cannot be spliced in at
        # runtime -- hence literal branches.
        case Keyword.get(opts, :via, []) do
          [] -> Ash.Expr.expr(map_id == ^map_id)
          [:self] -> Ash.Expr.expr(id == ^map_id)
          [:system] -> Ash.Expr.expr(system.map_id == ^map_id)
          [:acl] -> Ash.Expr.expr(exists(map_access_lists, map_id == ^map_id))
          [:access_list] -> Ash.Expr.expr(exists(access_list.map_access_lists, map_id == ^map_id))
        end
    end
  end
end
