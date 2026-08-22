defmodule WandererApp.Repo.Migrations.FixMapScopesDefault do
  @moduledoc """
  `maps_v1.scopes` was defaulted with `'{wormholes}'`, which Elixir reads as a
  charlist, so the column default became the character codes of "{wormholes}"
  rather than the array. Any row inserted without an explicit `scopes` came back
  as `["123", "119", ...]` and blew up on load as `{:array, :atom}`.

  ash_postgres still serializes the resource's `default([:wormholes])` to that
  charlist, so the column is corrected here rather than by regenerating.
  """

  use Ecto.Migration

  # The charlist default as Postgres stored it.
  @charlist_default "ARRAY['123','119','111','114','109','104','111','108','101','115','125']::text[]"

  def up do
    execute("ALTER TABLE maps_v1 ALTER COLUMN scopes SET DEFAULT ARRAY['wormholes']::text[]")

    execute("""
    UPDATE maps_v1
       SET scopes = ARRAY['wormholes']::text[]
     WHERE scopes = #{@charlist_default}
    """)
  end

  def down do
    execute("ALTER TABLE maps_v1 ALTER COLUMN scopes SET DEFAULT #{@charlist_default}")
  end
end
