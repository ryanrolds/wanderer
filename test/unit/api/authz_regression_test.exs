defmodule WandererApp.Api.AuthzRegressionTest do
  @moduledoc """
  Guards the six internal call sites that pass an `actor:` and therefore became
  policy-enforced when the domain adopted `authorize :when_requested`.

  These are the paths most likely to break silently: they worked before because
  nothing was authorized, and a policy that is stricter than the preparation it
  replaced would quietly shrink what the UI shows rather than raising.
  """

  use WandererApp.DataCase, async: false

  require Ash.Query

  alias WandererApp.Api.ActorHelpers
  alias WandererApp.Api.Authz
  alias WandererAppWeb.Factory

  defp user_with_character(attrs \\ %{}) do
    user = Factory.insert(:user)
    character = Factory.insert(:character, Map.put(attrs, :user_id, user.id))
    {:ok, user} = WandererApp.Api.User.by_id(user.id, load: [:characters], authorize?: false)
    {user, character}
  end

  describe "Acls.get_available_acls/1 (call site 1)" do
    test "an ACL owner still sees their ACL" do
      {user, character} = user_with_character()
      acl = Factory.insert(:access_list, %{owner_id: character.id, name: "owned"})

      {:ok, acls} = WandererApp.Acls.get_available_acls(user)

      assert acl.id in Enum.map(acls, & &1.id)
    end

    test "a :manager -- not only an :admin -- still sees the ACL" do
      {_owner_user, owner_character} = user_with_character()
      {member_user, member_character} = user_with_character()

      acl = Factory.insert(:access_list, %{owner_id: owner_character.id, name: "managed"})

      Factory.insert(:access_list_member, %{
        access_list_id: acl.id,
        name: "mgr",
        eve_character_id: member_character.eve_id,
        role: :manager
      })

      {:ok, acls} = WandererApp.Acls.get_available_acls(member_user)

      assert acl.id in Enum.map(acls, & &1.id),
             "the read policy must not be stricter than FilterAclsByRoles, which admits :manager"
    end

    test "an unrelated user sees nothing" do
      {_owner_user, owner_character} = user_with_character()
      {stranger, _} = user_with_character()

      acl = Factory.insert(:access_list, %{owner_id: owner_character.id, name: "private"})

      {:ok, acls} = WandererApp.Acls.get_available_acls(stranger)

      refute acl.id in Enum.map(acls, & &1.id)
    end

    test "a :viewer alongside an unrelated :admin does not inherit access" do
      # Regression for the flat-conjunction bug: the old filter could match the
      # character on one member row and the role on another.
      {_owner_user, owner_character} = user_with_character()
      {viewer_user, viewer_character} = user_with_character()
      {_admin_user, admin_character} = user_with_character()

      acl = Factory.insert(:access_list, %{owner_id: owner_character.id, name: "mixed"})

      Factory.insert(:access_list_member, %{
        access_list_id: acl.id,
        name: "viewer",
        eve_character_id: viewer_character.eve_id,
        role: :viewer
      })

      Factory.insert(:access_list_member, %{
        access_list_id: acl.id,
        name: "admin",
        eve_character_id: admin_character.eve_id,
        role: :admin
      })

      {:ok, acls} = WandererApp.Acls.get_available_acls(viewer_user)

      refute acl.id in Enum.map(acls, & &1.id),
             "a :viewer must not inherit access from a different member's :admin row"
    end
  end

  describe "Maps.get_available_maps/1 (call site 2)" do
    test "a map owner still sees their map" do
      {user, character} = user_with_character()
      map = Factory.insert(:map, %{owner_id: character.id})

      {:ok, maps} = WandererApp.Maps.get_available_maps(user)

      assert map.id in Enum.map(maps, & &1.id)
    end

    test "reach by corporation membership is preserved" do
      # The widest branch of level: :any, and the easiest to drop by accident.
      {_owner_user, owner_character} = user_with_character()
      corp_id = 98_000_000 + System.unique_integer([:positive])
      {corp_user, _corp_character} = user_with_character(%{corporation_id: corp_id})

      map = Factory.insert(:map, %{owner_id: owner_character.id})
      acl = Factory.insert(:access_list, %{owner_id: owner_character.id, name: "corp-acl"})

      Factory.insert(:access_list_member, %{
        access_list_id: acl.id,
        name: "the corp",
        eve_corporation_id: to_string(corp_id),
        role: :member
      })

      Factory.insert(:map_access_list, %{map_id: map.id, access_list_id: acl.id})

      {:ok, maps} = WandererApp.Maps.get_available_maps(corp_user)

      assert map.id in Enum.map(maps, & &1.id),
             "corporation-based ACL membership must still grant map visibility"
    end

    test "an unrelated user sees nothing" do
      {_owner_user, owner_character} = user_with_character()
      {stranger, _} = user_with_character()

      map = Factory.insert(:map, %{owner_id: owner_character.id})

      {:ok, maps} = WandererApp.Maps.get_available_maps(stranger)

      refute map.id in Enum.map(maps, & &1.id)
    end
  end

  describe "MapRepo.get_by_slug_with_permissions/2 (call site 3)" do
    test "resolves for a user with no access rather than raising" do
      # Circular case: :user_permissions computes the access level, so it must
      # load even when the answer is "none".
      {_owner_user, owner_character} = user_with_character()
      {stranger, _} = user_with_character()

      map = Factory.insert(:map, %{owner_id: owner_character.id})

      result = WandererApp.MapRepo.get_by_slug_with_permissions(map.slug, stranger)

      assert {:ok, loaded} = result
      assert is_integer(loaded.user_permissions)
    end

    test "resolves for the owner" do
      {user, character} = user_with_character()
      map = Factory.insert(:map, %{owner_id: character.id})

      assert {:ok, loaded} = WandererApp.MapRepo.get_by_slug_with_permissions(map.slug, user)
      assert is_integer(loaded.user_permissions)
    end
  end

  describe "Authz.can_manage_acl?/2" do
    test "false for a map key against an unbound ACL" do
      {owner_user, owner_character} = user_with_character()
      map = Factory.insert(:map, %{owner_id: owner_character.id})
      acl = Factory.insert(:access_list, %{owner_id: owner_character.id, name: "unbound"})

      actor = WandererApp.Api.ActorWithMap.new(owner_user, map)

      refute Authz.can_manage_acl?(actor, acl.id),
             "a map key must not reach an ACL that is not bound to its map, even one its own user owns"
    end

    test "true for a map key against an ACL bound to its map" do
      {owner_user, owner_character} = user_with_character()
      map = Factory.insert(:map, %{owner_id: owner_character.id})
      acl = Factory.insert(:access_list, %{owner_id: owner_character.id, name: "bound"})
      Factory.insert(:map_access_list, %{map_id: map.id, access_list_id: acl.id})

      actor = WandererApp.Api.ActorWithMap.new(owner_user, map)

      assert Authz.can_manage_acl?(actor, acl.id)
    end

    test "false for a nil actor and a nil acl id" do
      refute Authz.can_manage_acl?(nil, Ecto.UUID.generate())
      refute Authz.can_manage_acl?(nil, nil)
    end
  end

  describe "Authz.can_manage_map?/2" do
    test "a map key manages only its own map, never its user's other maps" do
      {owner_user, owner_character} = user_with_character()
      map_a = Factory.insert(:map, %{owner_id: owner_character.id})
      map_b = Factory.insert(:map, %{owner_id: owner_character.id})

      actor = WandererApp.Api.ActorWithMap.new(owner_user, map_a)

      assert Authz.can_manage_map?(actor, map_a.id)

      refute Authz.can_manage_map?(actor, map_b.id),
             "an ActorWithMap must not inherit its user's other maps"
    end

    test "a session user manages maps they own" do
      {user, character} = user_with_character()
      map = Factory.insert(:map, %{owner_id: character.id})

      assert Authz.can_manage_map?(user, map.id)
    end
  end

  describe "ActorHelpers.principal/1" do
    test "distinguishes a Character from a User" do
      {user, character} = user_with_character()

      assert {:user, _} = ActorHelpers.principal(user)

      assert {:character, _} = ActorHelpers.principal(character),
             "a Character must not be classified as a User; get_user/1's %{id: _} clause does exactly that"
    end

    test "classifies ActorWithMap by whether a map is present" do
      {user, _character} = user_with_character()
      map = Factory.insert(:map, %{})

      assert {:map_key, _, _} =
               ActorHelpers.principal(WandererApp.Api.ActorWithMap.new(user, map))

      assert {:user, _} = ActorHelpers.principal(WandererApp.Api.ActorWithMap.new(user, nil))
    end

    test "nil is :system and anything else is :unknown" do
      assert ActorHelpers.principal(nil) == :system
      assert ActorHelpers.principal(%{id: "not-a-resource"}) == :unknown
      assert ActorHelpers.principal("nonsense") == :unknown
    end
  end
end
