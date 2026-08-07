defmodule WandererApp.Api.Checks.CanManageTargetAcl do
  @moduledoc """
  Simple check for create actions: the `access_list_id` being written must name
  an ACL the actor may administer.

  A filter check cannot express this - on a create there is no row to filter
  against, and the relevant authority lives on the *target* ACL rather than on
  the record being written. This is what stops
  `POST /api/v1/access_list_members {access_list_id: <victim>, role: admin}`.
  """

  use Ash.Policy.SimpleCheck

  alias WandererApp.Api.Authz

  @impl true
  def describe(_opts), do: "actor may administer the target access list"

  @impl true
  def match?(actor, %{subject: %Ash.Changeset{} = changeset}, _opts) do
    acl_id =
      Ash.Changeset.get_attribute(changeset, :access_list_id) ||
        Ash.Changeset.get_argument(changeset, :access_list_id)

    Authz.can_manage_acl?(actor, acl_id)
  end

  def match?(_actor, _context, _opts), do: false
end
