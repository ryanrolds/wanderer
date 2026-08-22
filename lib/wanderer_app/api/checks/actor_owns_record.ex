defmodule WandererApp.Api.Checks.ActorOwnsRecord do
  @moduledoc """
  Filter check: the record's `user_id` is the acting user's own id.

  Used where map-scoping alone is too coarse. `MapUserSettings` has a composite
  primary key of `map_id` + `user_id`, so scoping it only by map would let any
  user holding any ACL role on a map read every other user's
  `main_character_eve_id`, `following_character_eve_id` and `hubs` for that map.

  Fails closed for map keys (they get a separate, deliberately map-wide branch,
  matching what the map UI already surfaces) and for absent actors.
  """

  use Ash.Policy.FilterCheck

  require Ash.Expr

  alias WandererApp.Api.ActorHelpers

  @impl true
  def describe(_opts), do: "record belongs to the acting user"

  @impl true
  def filter(actor, _context, _opts) do
    case ActorHelpers.principal(actor) do
      {:user, %{id: user_id}} ->
        Ash.Expr.expr(user_id == ^user_id)

      {:character, %{user_id: user_id}} when not is_nil(user_id) ->
        Ash.Expr.expr(user_id == ^user_id)

      _ ->
        Ash.Expr.expr(false)
    end
  end
end
