import { useCallback, useMemo, useState } from 'react';

import classes from './SolarSystemEdge.module.scss';
import { EdgeLabelRenderer, EdgeProps, getBezierPath, Position, useStore } from 'reactflow';
import { getEdgeParams } from '@/hooks/Mapper/components/map/utils.ts';
import clsx from 'clsx';
import { ConnectionType, MassState, ShipSizeStatus, SolarSystemConnection, TimeStatus } from '@/hooks/Mapper/types';
import { PrimeIcons } from 'primereact/api';
import { WdTooltipWrapper } from '@/hooks/Mapper/components/ui-kit/WdTooltipWrapper';
import { useMapState } from '@/hooks/Mapper/components/map/MapProvider.tsx';

const MAP_TRANSLATES: Record<string, string> = {
  [Position.Top]: 'translate(-48%, 0%)',
  [Position.Bottom]: 'translate(-50%, -100%)',
  [Position.Left]: 'translate(0%, -50%)',
  [Position.Right]: 'translate(-100%, -50%)',
};

const MAP_OFFSETS_TICK: Record<string, { x: number; y: number }> = {
  [Position.Top]: { x: 0, y: 3 },
  [Position.Bottom]: { x: 0, y: -3 },
  [Position.Left]: { x: 3, y: 0 },
  [Position.Right]: { x: -3, y: 0 },
};

const MAP_OFFSETS: Record<string, { x: number; y: number }> = {
  [Position.Top]: { x: 0, y: 0 },
  [Position.Bottom]: { x: 0, y: 0 },
  [Position.Left]: { x: 0, y: 0 },
  [Position.Right]: { x: 0, y: 0 },
};

export const SolarSystemEdge = ({ id, source, target, markerEnd, style, data }: EdgeProps<SolarSystemConnection>) => {
  const sourceNode = useStore(useCallback(store => store.nodeInternals.get(source), [source]));
  const targetNode = useStore(useCallback(store => store.nodeInternals.get(target), [target]));
  const isWormhole = data?.type !== ConnectionType.gate;

  const {
    data: { isThickConnections },
  } = useMapState();

  const [hovered, setHovered] = useState(false);

  const [path, labelX, labelY, sx, sy, tx, ty, sourcePos, targetPos] = useMemo(() => {
    const { sx, sy, tx, ty, sourcePos, targetPos } = getEdgeParams(sourceNode, targetNode);

    const offset = isThickConnections ? MAP_OFFSETS_TICK[targetPos] : MAP_OFFSETS[targetPos];

    const [edgePath, labelX, labelY] = getBezierPath({
      sourceX: sx - offset.x,
      sourceY: sy - offset.y,
      sourcePosition: sourcePos,
      targetPosition: targetPos,
      targetX: tx + offset.x,
      targetY: ty + offset.y,
    });
    return [edgePath, labelX, labelY, sx, sy, tx, ty, sourcePos, targetPos];
  }, [isThickConnections, sourceNode, targetNode]);

  if (!sourceNode || !targetNode || !data) {
    return null;
  }

  return (
    <>
      <path
        id={`back_${id}`}
        className={clsx(classes.EdgePathBack, {
          [classes.Tick]: isThickConnections,
          [classes.TimeCrit]: isWormhole && data.time_status === TimeStatus.eol,
          [classes.Hovered]: hovered,
        })}
        d={path}
        markerEnd={markerEnd}
        style={style}
      />
      <path
        id={`front_${id}`}
        className={clsx(classes.EdgePathFront, {
          [classes.Tick]: isThickConnections,
          [classes.Hovered]: hovered,
          [classes.MassVerge]: isWormhole && data.mass_status === MassState.verge,
          [classes.MassHalf]: isWormhole && data.mass_status === MassState.half,
          [classes.Frigate]: isWormhole && data.ship_size_type === ShipSizeStatus.small,
        })}
        d={path}
        markerEnd={markerEnd}
        style={style}
      />
      <path
        id={id}
        className={classes.ClickPath}
        d={path}
        markerEnd={markerEnd}
        style={style}
        onMouseEnter={() => setHovered(true)}
        onMouseLeave={() => setHovered(false)}
      />

      <EdgeLabelRenderer>
        <div
          className={clsx(
            classes.Handle,
            { [classes.Tick]: isThickConnections, [classes.Right]: Position.Right === sourcePos },
            'react-flow__handle absolute nodrag pointer-events-none',
          )}
          style={{ transform: `${MAP_TRANSLATES[sourcePos]} translate(${sx}px,${sy}px)` }}
        />
        <div
          className={clsx(
            classes.Handle,
            { [classes.Tick]: isThickConnections },
            'react-flow__handle absolute nodrag pointer-events-none',
          )}
          style={{ transform: `${MAP_TRANSLATES[targetPos]} translate(${tx}px,${ty}px)` }}
        />

        <div
          className="absolute flex items-center gap-1"
          style={{
            transform: `translate(-50%, -50%) translate(${labelX}px,${labelY}px)`,
          }}
        >
          {isWormhole && data.locked && (
            <WdTooltipWrapper
              content="Save mass"
              className={clsx(
                classes.LinkLabel,
                'pointer-events-auto bg-amber-300 rounded opacity-100 cursor-auto text-neutral-900',
              )}
            >
              <span className={clsx(PrimeIcons.LOCK, classes.icon)} />
            </WdTooltipWrapper>
          )}
        </div>
      </EdgeLabelRenderer>
    </>
  );
};
