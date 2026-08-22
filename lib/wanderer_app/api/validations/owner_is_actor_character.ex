defmodule WandererApp.Api.Validations.OwnerIsActorCharacter do
  @moduledoc """
  Validates that the `owner_id` being written names one of the acting user's own
  characters.

  Access lists are owned by a `Character`, and a user may have several, so the
  owner cannot simply be derived from the actor -- the client has to name one.
  Without this validation a logged-in user could mint an access list owned by
  somebody else's character, which is both a spoofing vector and, combined with
  a client-supplied `api_key`, a way to plant a credential on a record that
  looks like it belongs to another player.

  Fails closed when there is no actor. This is deliberate: the action it guards
  is reachable only over JSON:API, where `CheckJsonApiAuth` always supplies one.
  An actor-less call would otherwise skip both this validation's intent and the
  resource policies (which, under `authorize :when_requested`, do not run
  without an actor). Internal callers should use the primary `:new` action.
  """

  use Ash.Resource.Validation

  alias WandererApp.Api.ActorHelpers

  @impl true
  def validate(changeset, _opts, context) do
    owner_id =
      Ash.Changeset.get_attribute(changeset, :owner_id) ||
        Ash.Changeset.get_argument(changeset, :owner_id)

    actor = Map.get(context, :actor)

    case {owner_id, ActorHelpers.principal(actor)} do
      {nil, _} ->
        error(:owner_id, "is required")

      {_owner_id, principal} when principal in [:system, :unknown] ->
        error(
          :owner_id,
          "cannot be verified without an authenticated user; use the :new action for internal calls"
        )

      {owner_id, _principal} ->
        {character_ids, _eve_ids, _corp_ids, _alliance_ids} =
          ActorHelpers.character_identity(actor)

        if owner_id in character_ids do
          :ok
        else
          error(:owner_id, "must be one of your own characters")
        end
    end
  end

  defp error(field, message) do
    {:error, Ash.Error.Changes.InvalidAttribute.exception(field: field, message: message)}
  end
end
