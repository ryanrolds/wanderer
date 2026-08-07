defmodule WandererApp.Api.ActorHelpers do
  @moduledoc """
  Utilities for extracting actor information from Ash contexts.

  Provides helper functions for working with ActorWithMap and extracting
  user, map, and character information from various context formats.
  """

  alias WandererApp.Api.ActorWithMap

  @doc """
  Extract map from actor or context.

  Handles various context formats:
  - Direct ActorWithMap struct
  - Context map with :actor key
  - Context map with :map key
  - Ash.Resource.Change.Context struct
  """
  def get_map(%{actor: %ActorWithMap{map: %{} = map}}), do: map
  def get_map(%{map: %{} = map}), do: map

  # Handle Ash.Resource.Change.Context struct
  def get_map(%Ash.Resource.Change.Context{actor: %ActorWithMap{map: %{} = map}}), do: map
  def get_map(%Ash.Resource.Change.Context{actor: _}), do: nil

  def get_map(context) when is_map(context) do
    # For plain maps, check private.actor
    with private when is_map(private) <- Map.get(context, :private),
         %ActorWithMap{map: %{} = map} <- Map.get(private, :actor) do
      map
    else
      _ -> nil
    end
  end

  def get_map(_), do: nil

  @doc """
  Extract user from actor.

  Handles:
  - ActorWithMap struct
  - Direct user struct with :id field
  """
  def get_user(%ActorWithMap{user: user}), do: user
  def get_user(%{id: _} = user), do: user
  def get_user(_), do: nil

  @doc """
  Get character IDs for the actor.

  Used for ACL filtering to determine which resources the user can access.
  Returns {:ok, list} or {:ok, []} if no characters found.
  """
  def get_character_ids(%ActorWithMap{user: user}), do: get_character_ids(user)

  def get_character_ids(%{characters: characters}) when is_list(characters) do
    {:ok, Enum.map(characters, & &1.id)}
  end

  def get_character_ids(%{characters: %Ecto.Association.NotLoaded{}, id: user_id}) do
    # Load characters from database
    load_characters_by_id(user_id)
  end

  def get_character_ids(%{id: user_id}) do
    # Fallback: load user with characters
    load_characters_by_id(user_id)
  end

  def get_character_ids(_), do: {:ok, []}

  defp load_characters_by_id(user_id) do
    case WandererApp.Api.User.by_id(user_id, load: [:characters]) do
      {:ok, user} -> {:ok, Enum.map(user.characters, & &1.id)}
      _ -> {:ok, []}
    end
  end

  # ---------------------------------------------------------------------------
  # Policy support
  #
  # The functions above predate policies and are kept as-is because
  # FilterByActorMap and InjectMapFromActor depend on them. Everything below is
  # for `WandererApp.Api.Checks.*` and `WandererApp.Api.Authz`.
  # ---------------------------------------------------------------------------

  @typedoc """
  Canonical principal for policy checks.

    * `{:map_key, user, map}` - bearer map API key; scoped to exactly one map
    * `{:user, user}`         - session / LiveView; scoped by ACL membership
    * `{:character, char}`    - internal LiveView call passing a bare character
    * `:system`               - no actor; internal trusted call
    * `:unknown`              - unrecognised actor shape; treated as no access
  """
  @type principal ::
          {:map_key, struct(), struct()}
          | {:user, struct()}
          | {:character, struct()}
          | :system
          | :unknown

  @doc """
  Classify an actor into a `t:principal/0`.

  Unlike `get_user/1`, this matches struct modules explicitly so a `Character`
  can never be mistaken for a `User`.
  """
  @spec principal(term()) :: principal()
  def principal(%ActorWithMap{map: %{id: _} = map, user: user}), do: {:map_key, user, map}
  def principal(%ActorWithMap{map: nil, user: user}), do: {:user, user}
  def principal(nil), do: :system

  def principal(actor) when is_struct(actor) do
    cond do
      is_struct(actor, WandererApp.Api.User) -> {:user, actor}
      is_struct(actor, WandererApp.Api.Character) -> {:character, actor}
      true -> :unknown
    end
  end

  def principal(_), do: :unknown

  @doc """
  Map id for a bearer-map-key actor, else `nil`.

  Deliberately never falls back to a user's other maps: an `ActorWithMap` is
  scoped to the single map its API key belongs to.
  """
  @spec actor_map_id(term()) :: String.t() | nil
  def actor_map_id(actor) do
    case principal(actor) do
      {:map_key, _user, map} -> map.id
      _ -> nil
    end
  end

  @doc """
  Character identity tuple for ACL matching, loading characters if needed.

  Returns `{ids, eve_ids, corporation_ids, alliance_ids}`. `ids` are character
  UUIDs; the rest are strings, matching how they are stored on
  `AccessListMember`.
  """
  @spec character_identity(term()) :: {[String.t()], [String.t()], [String.t()], [String.t()]}
  def character_identity(actor) do
    characters =
      case principal(actor) do
        {:map_key, user, _map} -> load_characters(user)
        {:user, user} -> load_characters(user)
        {:character, character} -> [character]
        _ -> []
      end

    {
      Enum.map(characters, & &1.id),
      characters |> Enum.map(& &1.eve_id) |> Enum.reject(&is_nil/1),
      characters
      |> Enum.map(& &1.corporation_id)
      |> Enum.reject(&is_nil/1)
      |> Enum.map(&to_string/1),
      characters |> Enum.map(& &1.alliance_id) |> Enum.reject(&is_nil/1) |> Enum.map(&to_string/1)
    }
  end

  defp load_characters(%{characters: characters}) when is_list(characters), do: characters

  defp load_characters(%{id: user_id}) do
    # authorize?: false is required: this call *is* part of an authorization
    # decision and must not recurse into the policies that triggered it.
    case WandererApp.Api.User.by_id(user_id, load: [:characters], authorize?: false) do
      {:ok, %{characters: characters}} when is_list(characters) -> characters
      _ -> []
    end
  end

  defp load_characters(_), do: []
end
