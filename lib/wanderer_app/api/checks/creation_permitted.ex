defmodule WandererApp.Api.Checks.CreationPermitted do
  @moduledoc """
  Simple check honouring the deployment-level creation restrictions in
  `WandererApp.Env`.

  Until now these were enforced only in the LiveView UI
  (`access_lists_live.ex`, `maps_live.ex`) and were bypassable via
  `POST /api/v1/access_lists` and `POST /api/v1/maps`. A flag that only stops
  the UI is a suggestion, not a restriction.

  Options: `:flag` - `:maps` or `:acls`.

  Both `Env` functions are `@decorate cacheable`, so this is a cache read rather
  than a database hit.
  """

  use Ash.Policy.SimpleCheck

  @impl true
  def describe(opts), do: "#{Keyword.fetch!(opts, :flag)} creation is not restricted"

  @impl true
  def match?(_actor, _context, opts) do
    case Keyword.fetch!(opts, :flag) do
      :maps -> not WandererApp.Env.restrict_maps_creation?()
      :acls -> not WandererApp.Env.restrict_acls_creation?()
    end
  end
end
