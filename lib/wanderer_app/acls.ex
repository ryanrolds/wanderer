defmodule WandererApp.Acls do
  @moduledoc false

  # get_available_acls/0 removed: no callers, and it returned every ACL in the
  # deployment. FilterAclsByRoles now fails closed on a nil actor to match.

  def get_available_acls(current_user) do
    case WandererApp.Api.AccessList.available(%{}, actor: current_user) do
      {:ok, acls} -> {:ok, acls |> Enum.sort_by(& &1.name, :asc)}
      _ -> {:ok, []}
    end
  end
end
