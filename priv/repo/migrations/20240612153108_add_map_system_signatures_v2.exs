defmodule WandererApp.Repo.Migrations.AddMapSystemSignaturesV2 do
  @moduledoc """
  Updates resources based on their most recent snapshots.

  This file was autogenerated with `mix ash_postgres.generate_migrations`
  """

  use Ecto.Migration

  def up do
    alter table(:map_system_signatures_v1) do
      modify :name, :text, null: true
      add :character_eve_id, :text, null: false
    end
  end

  def down do
    alter table(:map_system_signatures_v1) do
      remove :character_eve_id
      modify :name, :text, null: false
    end
  end
end
