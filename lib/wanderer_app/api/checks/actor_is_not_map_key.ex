defmodule WandererApp.Api.Checks.ActorIsNotMapKey do
  @moduledoc """
  Simple check: the actor is an interactive principal (a session user, or a bare
  character from an internal LiveView/controller path) rather than a bearer map
  API key.

  Used to keep resource *creation* out of reach of map API keys. A map key must
  not be able to mint a new map or ACL: a freshly created ACL is bound to no
  map, so no map-scoped read policy could ever govern it afterwards.

  Both `{:user, _}` and `{:character, _}` qualify. The codebase passes actors in
  both shapes -- `WandererApp.Acls.get_available_acls/1` passes a `User`, while
  `map_core_event_handler.ex` and the map duplication path in
  `MapAPIController` pass a bare `Character`. Neither is a bearer key, which is
  the distinction that matters here.

  `:system` (no actor) and `:unknown` are rejected. Under
  `authorize :when_requested` a genuinely internal call passes no actor at all
  and is never authorized, so reaching this check with `:system` means someone
  passed `actor: nil` explicitly -- which should not grant creation rights.
  """

  use Ash.Policy.SimpleCheck

  alias WandererApp.Api.ActorHelpers

  @impl true
  def describe(_opts), do: "actor is not a bearer map API key"

  @impl true
  def match?(actor, _context, _opts) do
    case ActorHelpers.principal(actor) do
      {:user, _} -> true
      {:character, _} -> true
      _ -> false
    end
  end
end
