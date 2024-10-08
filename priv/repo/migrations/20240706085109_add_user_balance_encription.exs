defmodule WandererApp.Repo.Migrations.AddUserBalanceEncription do
  @moduledoc """
  Updates resources based on their most recent snapshots.

  This file was autogenerated with `mix ash_postgres.generate_migrations`
  """

  use Ecto.Migration

  def up do
    alter table(:user_v1) do
      add :encrypted_balance, :binary
    end
  end

  def down do
    alter table(:user_v1) do
      remove :encrypted_balance
    end
  end
end
