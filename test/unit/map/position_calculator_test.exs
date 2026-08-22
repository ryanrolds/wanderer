defmodule WandererApp.Map.PositionCalculatorTest do
  @moduledoc """
  Tests for automatic system placement.

  The calculator reaches the spatial index through `@ddrt`, which is compile-time
  bound to `Test.DDRTMock` in the test env. Most tests here delegate that mock to
  the real `CacheRTree` so the ring search and the collision check are exercised
  together — the suite's default stub answers every query with `{:ok, []}`, which
  makes every candidate position look free and hides the whole collision path.
  """
  use ExUnit.Case, async: false

  import Mox

  alias WandererApp.Map.CacheRTree
  alias WandererApp.Map.PositionCalculator

  # Node box is 130x34; the grid step is node + margin (180x75).
  @w 130
  @h 34

  setup do
    tree_name = "test_poscalc_#{:rand.uniform(1_000_000)}"
    CacheRTree.init_tree(tree_name)
    on_exit(fn -> CacheRTree.clear_tree(tree_name) end)

    {:ok, tree_name: tree_name}
  end

  defp use_real_rtree do
    Test.DDRTMock
    |> stub(:query, fn bbox, name -> CacheRTree.query(bbox, name) end)
    |> stub(:insert, fn leaf, name -> CacheRTree.insert(leaf, name) end)
  end

  defp occupy(name, positions) do
    positions
    |> Enum.with_index()
    |> Enum.each(fn {{x, y}, i} ->
      CacheRTree.insert(
        {30_000_000 + i,
         PositionCalculator.get_system_bounding_rect(%{position_x: x, position_y: y})},
        name
      )
    end)
  end

  defp boxes_overlap?({ax, ay}, {bx, by}) do
    ax < bx + @w and bx < ax + @w and ay < by + @h and by < ay + @h
  end

  describe "get_system_bounding_rect/1" do
    test "returns the node box anchored at the position" do
      assert [{100, 230}, {50, 84}] =
               PositionCalculator.get_system_bounding_rect(%{position_x: 100, position_y: 50})
    end

    test "falls back to a degenerate box for a system without a position" do
      assert [{0, 0}, {0, 0}] = PositionCalculator.get_system_bounding_rect(%{})
    end
  end

  describe "get_available_positions/4 ring geometry" do
    test "level N yields the 4N*2 cells of that square ring, without duplicates" do
      for {level, count} <- [{1, 8}, {2, 16}, {3, 24}] do
        positions =
          PositionCalculator.get_available_positions(level, 0, 0, layout: "left_to_right")

        assert length(positions) == count
        assert length(Enum.uniq(positions)) == count
      end
    end

    test "left_to_right starts directly right of the origin and sweeps clockwise" do
      assert [
               {180, 0},
               {180, 75},
               {0, 75},
               {-180, 75},
               {-180, 0},
               {-180, -75},
               {0, -75},
               {180, -75}
             ] = PositionCalculator.get_available_positions(1, 0, 0, layout: "left_to_right")
    end

    test "top_to_bottom starts directly below the origin" do
      assert [{1000, 575} | _] =
               PositionCalculator.get_available_positions(1, 1000, 500, layout: "top_to_bottom")
    end

    test "a nil layout behaves as left_to_right" do
      assert PositionCalculator.get_available_positions(1, 0, 0, layout: nil) ==
               PositionCalculator.get_available_positions(1, 0, 0, layout: "left_to_right")
    end

    test "ring N is offset by N grid steps from the origin" do
      assert [{1360, 500} | _] =
               PositionCalculator.get_available_positions(2, 1000, 500, layout: "left_to_right")
    end
  end

  describe "get_new_system_position/3" do
    test "places the first system of a map near the map origin", %{tree_name: name} do
      use_real_rtree()

      assert %{x: 180, y: 0} =
               PositionCalculator.get_new_system_position(nil, name, layout: "left_to_right")
    end

    test "places a system relative to the origin system it was reached from", %{tree_name: name} do
      use_real_rtree()

      origin = %{position_x: 1000, position_y: 500}

      assert %{x: 1180, y: 500} =
               PositionCalculator.get_new_system_position(origin, name, layout: "left_to_right")
    end

    test "honours the map's top_to_bottom layout", %{tree_name: name} do
      use_real_rtree()

      origin = %{position_x: 1000, position_y: 500}

      assert %{x: 1000, y: 575} =
               PositionCalculator.get_new_system_position(origin, name, layout: "top_to_bottom")
    end

    test "skips an occupied slot and takes the next one on the ring", %{tree_name: name} do
      use_real_rtree()
      occupy(name, [{1180, 500}])

      origin = %{position_x: 1000, position_y: 500}

      assert %{x: 1180, y: 575} =
               PositionCalculator.get_new_system_position(origin, name, layout: "left_to_right")
    end

    test "escalates to the next ring when the whole ring is occupied", %{tree_name: name} do
      use_real_rtree()

      occupy(
        name,
        PositionCalculator.get_available_positions(1, 1000, 500, layout: "left_to_right")
      )

      origin = %{position_x: 1000, position_y: 500}

      assert %{x: 1360, y: 500} =
               PositionCalculator.get_new_system_position(origin, name, layout: "left_to_right")
    end

    test "falls back to the map origin when every ring is exhausted", %{tree_name: name} do
      stub(Test.DDRTMock, :query, fn _bbox, _name -> {:ok, [30_000_142]} end)

      origin = %{position_x: 1000, position_y: 500}

      assert %{x: 0, y: 0} =
               PositionCalculator.get_new_system_position(origin, name, layout: "left_to_right")
    end

    test "never returns a position overlapping an already placed system", %{tree_name: name} do
      use_real_rtree()
      :rand.seed(:exsss, {101, 102, 103})

      placed =
        Enum.reduce(1..60, [], fn i, acc ->
          origin =
            case acc do
              [] -> nil
              _ -> Enum.random(acc) |> then(fn {x, y} -> %{position_x: x, position_y: y} end)
            end

          %{x: x, y: y} =
            PositionCalculator.get_new_system_position(origin, name, layout: "left_to_right")

          refute Enum.any?(acc, &boxes_overlap?({x, y}, &1)),
                 "system #{i} was placed at {#{x}, #{y}}, overlapping an existing system"

          CacheRTree.insert(
            {30_000_000 + i,
             PositionCalculator.get_system_bounding_rect(%{position_x: x, position_y: y})},
            name
          )

          [{x, y} | acc]
        end)

      assert length(placed) == 60
    end
  end

  describe "spatial index failures" do
    # `CacheRTree.query/2` rescues every exception into `{:error, term}`, so a failed
    # lookup must fail closed — read as free space it places the new system on top of
    # an existing one.
    test "a failing query does not make an occupied slot look available", %{tree_name: name} do
      occupied = PositionCalculator.get_system_bounding_rect(%{position_x: 1180, position_y: 500})

      Test.DDRTMock
      |> stub(:query, fn
        ^occupied, _name -> {:error, :index_unavailable}
        bbox, tree -> CacheRTree.query(bbox, tree)
      end)

      occupy(name, [{1180, 500}])

      origin = %{position_x: 1000, position_y: 500}

      refute %{x: 1180, y: 500} ==
               PositionCalculator.get_new_system_position(origin, name, layout: "left_to_right")
    end

    # `get_grid_cells/1` floor-divides the box corners. `div/2` raises on floats, which
    # dropped fractionally-positioned systems out of the grid entirely and let later
    # systems be placed on top of them.
    test "the index accepts fractional coordinates", %{tree_name: name} do
      assert {:ok, _} = CacheRTree.insert({30_000_142, [{100.5, 230.5}, {50.5, 84.5}]}, name)
      assert {:ok, [30_000_142]} = CacheRTree.query([{150, 200}, {60, 80}], name)
    end

    test "a query with fractional coordinates does not error", %{tree_name: name} do
      occupy(name, [{100, 50}])

      assert {:ok, [_]} = CacheRTree.query([{100.5, 230.5}, {50.5, 84.5}], name)
    end

    test "a system placed at fractional coordinates still blocks that slot", %{tree_name: name} do
      use_real_rtree()

      CacheRTree.insert(
        {30_000_142,
         PositionCalculator.get_system_bounding_rect(%{position_x: 1180.4, position_y: 500.2})},
        name
      )

      origin = %{position_x: 1000, position_y: 500}

      refute %{x: 1180, y: 500} ==
               PositionCalculator.get_new_system_position(origin, name, layout: "left_to_right")
    end
  end
end
