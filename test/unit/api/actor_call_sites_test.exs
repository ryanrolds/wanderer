defmodule WandererApp.Api.ActorCallSitesTest do
  @moduledoc """
  Guard rail for the `authorize :when_requested` rollout.

  The `WandererApp.Api` domain authorizes a call when the options carry an
  `:actor` key -- `Ash.Actions.Helpers` tests `Keyword.has_key?(opts, :actor)`,
  so even `actor: nil` opts in. Internal calls that pass no actor are trusted
  and unauthorized; that is what makes the change tractable, since the codebase
  has hundreds of internal Ash calls in GenServers and jobs with little test
  coverage.

  The corollary is that adding `actor:` to an internal call silently subjects it
  to resource policies, and the symptom is an `Ash.Error.Forbidden` at runtime
  in a code path no test exercises. This test turns that into a red build.

  If you are here because this test failed: decide which case you are in.

    * The call SHOULD be authorized -- the actor is a real principal and the
      resource's policies admit it. Add the file to @allowed with a note.
    * The call is internal and must stay trusted. Add `authorize?: false`
      alongside the actor, with a comment explaining why, then add the file to
      @allowed.

  Do not add a file to @allowed without checking the relevant resource's
  `policies do` block first.
  """

  use ExUnit.Case, async: true

  @allowed [
    # Domain definition -- contains the `authorize :when_requested` comment.
    "lib/wanderer_app/api.ex",

    # Authorization machinery itself.
    "lib/wanderer_app/api/actor_helpers.ex",
    "lib/wanderer_app/api/checks/actor_is_not_map_key.ex",
    "lib/wanderer_app/api/preparations/filter_acls_by_roles.ex",
    "lib/wanderer_app/api/preparations/filter_maps_by_roles.ex",
    "lib/wanderer_app/api/calculations/calc_map_permissions.ex",

    # Intentionally authorized: policies mirror the preparations these rely on.
    # Covered by test/unit/api/authz_regression_test.exs.
    "lib/wanderer_app/acls.ex",
    "lib/wanderer_app/maps.ex",
    "lib/wanderer_app_web/controllers/map_api_controller.ex",

    # Intentionally NOT authorized -- each carries `authorize?: false` and a
    # comment giving the reason.
    "lib/wanderer_app/repositories/map_repo.ex",
    "lib/wanderer_app_web/live/maps/maps_live.ex",
    "lib/wanderer_app_web/live/map/event_handlers/map_core_event_handler.ex"
  ]

  test "every lib/ file passing an actor: is a reviewed call site" do
    found =
      "lib/**/*.ex"
      |> Path.wildcard()
      |> Enum.filter(&(File.read!(&1) =~ ~r/\bactor:/))
      |> Enum.sort()

    expected = Enum.sort(@allowed)

    added = found -- expected
    removed = expected -- found

    assert added == [],
           """
           New file(s) pass `actor:` to an Ash call and were not reviewed:

               #{Enum.join(added, "\n    ")}

           Under `authorize :when_requested` this opts those calls into policy
           enforcement. Read this module's docstring before adding them to
           @allowed.
           """

    assert removed == [],
           """
           File(s) in @allowed no longer pass `actor:`:

               #{Enum.join(removed, "\n    ")}

           Remove them from @allowed to keep this guard meaningful.
           """
  end

  test "each deliberately-unauthorized site still carries authorize?: false" do
    for path <- [
          "lib/wanderer_app/repositories/map_repo.ex",
          "lib/wanderer_app_web/live/maps/maps_live.ex",
          "lib/wanderer_app_web/live/map/event_handlers/map_core_event_handler.ex"
        ] do
      assert File.read!(path) =~ "authorize?: false",
             "#{path} passes an actor but no longer opts out of authorization"
    end
  end
end
