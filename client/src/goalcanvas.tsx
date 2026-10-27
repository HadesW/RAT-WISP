// Attack-chain canvas for goals: React Flow view over the ordered step list.
// Layout is auto (grid) + free drag persisted per-goal in localStorage.
import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  ReactFlow, Background, Controls, Handle, Position, MarkerType,
  type Edge, type Node, type NodeProps,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';

export interface GStep { id: string; seq: number; name: string; kind: string; args: string; status: string; result: string }

const ICON: Record<string, string> = { task: '⚡', plugin: '🧩', gate: '🛡', wait: '⏱', note: '📝' };
const DOT: Record<string, string> = {
  pending: 'var(--text-dim)', running: 'var(--info)', awaiting: 'var(--warn)',
  done: 'var(--ok)', failed: 'var(--err)', skipped: 'var(--text-dim)',
};

interface StepData { step: GStep; editable: boolean; onGate: (id: string, ok: boolean) => void; onDel: (id: string) => void; approve: string; reject: string }

function StepNode({ data, selected }: NodeProps) {
  const { step, editable, onGate, onDel, approve, reject } = data as unknown as StepData;
  return (
    <div className="gnode" style={{ ['--dot' as never]: DOT[step.status] ?? 'var(--text-dim)' }}>
      <Handle type="target" position={Position.Left} />
      <div className="gnode-hd">
        <span>{ICON[step.kind] ?? '•'}</span>
        <b>{step.seq}. {step.name}</b>
        {editable && <span className="gnode-x" onClick={() => onDel(step.id)}>✕</span>}
      </div>
      <div className="gnode-sub">
        <i>{step.kind}</i>
        <span style={{ color: DOT[step.status] }}>{step.status}</span>
      </div>
      {step.result && <pre className="gnode-res" title={step.result}>{step.result.slice(0, 160)}</pre>}
      {step.status === 'awaiting' && step.kind === 'gate' && (
        <div className="gnode-gate">
          <button className="p" onClick={() => onGate(step.id, true)}>{approve}</button>
          <button onClick={() => onGate(step.id, false)}>{reject}</button>
        </div>
      )}
      <Handle type="source" position={Position.Right} />
      {selected && <span className="gnode-sel" />}
    </div>
  );
}

function StartNode({ data }: NodeProps) {
  const { title, status } = data as unknown as { title: string; status: string };
  return (
    <div className="gstart">
      <b>🎯 {title}</b>
      <i>{status}</i>
      <Handle type="source" position={Position.Right} />
    </div>
  );
}

const NODE_TYPES = { step: StepNode, start: StartNode };

function loadPos(goalId: string): Record<string, { x: number; y: number }> {
  try { return JSON.parse(localStorage.getItem(`wispp-goal-pos:${goalId}`) ?? '{}'); } catch { return {}; }
}

export function GoalCanvas({ goalId, title, goalStatus, steps, onGate, onDel, approve, reject, onSel }: {
  goalId: string; title: string; goalStatus: string; steps: GStep[];
  onGate: (id: string, ok: boolean) => void; onDel: (id: string) => void; approve: string; reject: string;
  onSel?: (id: string | null) => void;
}) {
  const [pos, setPos] = useState<Record<string, { x: number; y: number }>>({});
  useEffect(() => { setPos(loadPos(goalId)); }, [goalId]);

  const editable = goalStatus === 'draft' || goalStatus === 'paused';

  const { nodes, edges } = useMemo(() => {
    const perRow = 4;
    const auto = (i: number) => ({ x: 30 + (i % perRow) * 250, y: 30 + Math.floor(i / perRow) * 170 });
    const ns: Node[] = [{
      id: 'start', type: 'start', position: { x: -210, y: 40 },
      data: { title, status: goalStatus }, draggable: false,
    }];
    steps.forEach((st, i) => {
      ns.push({
        id: st.id, type: 'step', position: pos[st.id] ?? auto(i),
        data: { step: st, editable, onGate, onDel, approve, reject },
      });
    });
    const es: Edge[] = steps.map((st, i) => {
      const from = i === 0 ? 'start' : steps[i - 1].id;
      return {
        id: `${from}->${st.id}`, source: from, target: st.id,
        animated: st.status === 'running' || st.status === 'awaiting',
        style: { stroke: st.status === 'failed' ? 'var(--err)' : st.status === 'done' ? 'var(--ok)' : 'var(--border2)' },
        markerEnd: { type: MarkerType.ArrowClosed, width: 16, height: 16, color: 'var(--border2)' },
      };
    });
    if (!steps.length) es.push({ id: 'start->none', source: 'start', target: 'start', style: { opacity: 0 } });
    return { nodes: ns, edges: es };
  }, [steps, pos, title, goalStatus, editable, onGate, onDel, approve, reject]);

  const onNodesChange = useCallback((ch: { type: string; id?: string; position?: { x: number; y: number } }[]) => {
    const drag = ch.filter((c) => c.type === 'position' && c.id && c.position);
    if (!drag.length) return;
    setPos((p) => {
      const nx = { ...p };
      for (const c of drag) nx[c.id!] = c.position!;
      localStorage.setItem(`wispp-goal-pos:${goalId}`, JSON.stringify(nx));
      return nx;
    });
  }, [goalId]);

  return (
    <div className="gcanvas">
      <ReactFlow
        key={`${goalId}:${steps.length}:${goalStatus}`}
        nodes={nodes}
        edges={edges}
        nodeTypes={NODE_TYPES}
        onNodesChange={onNodesChange as never}
        fitView
        fitViewOptions={{ padding: 0.22 }}
        proOptions={{ hideAttribution: true }}
        nodesConnectable={false}
        minZoom={0.3}
        onNodeClick={(_, n) => onSel?.(n.id === 'start' ? null : n.id)}
        onPaneClick={() => onSel?.(null)}
      >
        <Background gap={18} size={1} />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
}
