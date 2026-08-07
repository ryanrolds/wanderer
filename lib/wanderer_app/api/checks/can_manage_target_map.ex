defmodule WandererApp.Api.Checks.CanManageTargetMap do
  @moduledoc """
  Simple check for create actions: the `map_id` being written must name a map
  the actor may administer.

  Counterpart to `WandererApp.Api.Checks.CanManageTargetAcl` for the map side of
  a `MapAccessList` binding, and for the Group A resources that carry a
  `map_id`.
  """

  use Ash.Policy.SimpleCheck

  alias WandererApp.Api.Authz

  @impl true
  def describe(_opts), do: "actor may administer the target map"

  @impl true
  def match?(actor, %{subject: %Ash.Changeset{} = changeset}, _opts) do
    map_id =
      Ash.Changeset.get_attribute(changeset, :map_id) ||
        Ash.Changeset.get_argument(changeset, :map_id)

    Authz.can_manage_map?(actor, map_id)
  end

  def match?(_actor, _context, _opts), do: false
end
