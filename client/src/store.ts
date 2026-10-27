import { create } from 'zustand';
import type { FileJob, Project, Session, TaskRecord, TeamEvent } from './types';
import { useI18n } from './i18n';

export const CMD_NAMES: Record<number, string> = {
  1: 'shell', 9: 'sysinfo', 10: 'sleep', 11: 'exit',
  12: 'ls', 13: 'mkdir', 14: 'rm', 23: 'rcp', 25: 'screenshot', 69: 'ps', 26: 'pwd', 27: 'kill', 65: 'p2p', 66: 'p2pstop',
};

// Dev/QoL convenience: /?token=xxx pre-fills the login (kept out of history
// by stripping the query on startup).
const urlTok = new URLSearchParams(window.location.search).get('token');
if (urlTok) {
  localStorage.setItem('wisp_token', urlTok);
  window.history.replaceState(null, '', window.location.pathname);
}

export type Rail = 'wide' | 'narrow';
export interface Toast {
  id: number;
  kind: 'ok' | 'err' | 'info';
  text: string;
  action?: { label: string; run: () => void };
}

export type DynKind = 'files' | 'term' | 'view' | 'info' | 'payload' | 'lsn' | 'plugin' | 'report' | 'goal' | 'fserver' | 'proxies' | 'loot' | 'timeline' | 'metrics';
export interface DynTab { id: string; kind: DynKind; session?: string }

interface Store {
  token: string;
  view: 'sessions' | 'agent';
  agentId: string;
  agentSection: 'files' | 'proc' | 'fwd';
  agentTab: 'main' | 'mon' | 'info';
  modal: 'settings' | null;
  rail: Rail;
  project: string;
  setProject: (p: string) => void;
  theme: 'dark' | 'light';
  setTheme: (t: 'dark' | 'light') => void;
  toggleTheme: () => void;
  aiW: number;
  aiOpen: boolean;
  setAiOpen: (v: boolean) => void;
  toggleAiOpen: () => void;
  bottomH: number;
  toggleRail: () => void;
  setView: (v: 'sessions' | 'agent') => void;
  openAgent: (id: string, opts?: { section?: 'files' | 'proc' | 'fwd'; tab?: 'main' | 'mon' | 'info' }) => void;
  closeAgent: () => void;
  setModal: (m: 'settings' | null) => void;
  setAIW: (w: number) => void;
  setBottomH: (h: number) => void;
  sessions: Session[];
  projects: Project[];
  tasks: TaskRecord[];
  jobs: FileJob[];
  events: TeamEvent[];
  selected: string; // session id
  sseUp: boolean;
  error: string;
  toasts: Toast[];
  toast: (t: Omit<Toast, 'id'>) => void;
  dismissToast: (id: number) => void;
  shotReq: string; // session id queued for one-shot screenshot (ctx menu)
  reqShot: (id: string) => void;
  clearShot: () => void;
  goalTick: number;
  helpOpen: boolean;
  setHelpOpen: (v: boolean) => void;
  dynTabs: DynTab[];
  activeTab: string; // 'console' | 'logs' | dynTab.id
  openTab: (kind: DynKind, session?: string) => void;
  closeTab: (id: string) => void;
  setActiveTab: (id: string) => void;
  setToken: (t: string) => void;
  setSelected: (id: string) => void;
  refresh: () => Promise<void>;
  connectSSE: () => void;
  dispatch: (session: string, cmd: string, args: unknown) => Promise<void>;
  runTask: (session: string, cmd: string, args: unknown, timeoutMs?: number) => Promise<TaskRecord>;
}

const api = (path: string, init?: RequestInit) => {
  const tok = localStorage.getItem('wisp_token') ?? '';
  return fetch(path, {
    ...init,
    headers: { 'X-Wisp-Token': tok, 'Content-Type': 'application/json', ...(init?.headers ?? {}) },
  });
};

const storedRail = (localStorage.getItem('wisp_rail') as Rail | null) ?? 'wide';

export const useStore = create<Store>((set, get) => ({
  token: localStorage.getItem('wisp_token') ?? '',
  view: 'sessions',
  modal: null,
  setView: (v) => set({ view: v, ...(v === 'sessions' ? { agentId: '' } : {}) }),
  agentId: '',
  agentSection: 'files',
  agentTab: 'main',
  openAgent: (id, opts) => set({
    view: 'agent',
    agentId: id,
    selected: id,
    agentSection: opts?.section ?? 'files',
    agentTab: opts?.tab ?? 'main',
  }),
  closeAgent: () => {
    const { agentId, dynTabs, activeTab } = get();
    // back closes every page opened for this agent; no agent UI state remains
    const left = dynTabs.filter((t) => t.session !== agentId);
    set({
      view: 'sessions',
      agentId: '',
      dynTabs: left,
      activeTab: left.some((t) => t.id === activeTab) ? activeTab : 'console',
    });
  },
  setModal: (m) => set({ modal: m }),
  rail: storedRail,
  project: localStorage.getItem('wisp_project') ?? '',
  setProject: (p) => {
    localStorage.setItem('wisp_project', p);
    const { sessions, selected, view, agentId } = get();
    const inProj = (s: Session) => !p || s.project === p;
    const nextSelected = sessions.some((s) => s.id === selected && inProj(s))
      ? selected
      : (sessions.find(inProj)?.id ?? '');
    const agentOut = view === 'agent' && !sessions.some((s) => s.id === agentId && inProj(s));
    set({
      project: p,
      selected: nextSelected,
      ...(agentOut ? { view: 'sessions' as const, agentId: '' } : {}),
    });
    void get().refresh().catch(() => {});
  },
  aiW: Number(localStorage.getItem('wisp_aiw') ?? 340),
  // Operator preference only; narrow viewports are collapsed at runtime
  // by the squeeze guard in App (kept out of localStorage).
  aiOpen: localStorage.getItem('wisp_ai_open') !== '0',
  setAiOpen: (v) => {
    localStorage.setItem('wisp_ai_open', v ? '1' : '0');
    set({ aiOpen: v });
  },
  toggleAiOpen: () => get().setAiOpen(!get().aiOpen),
  setAIW: (w) => {
    localStorage.setItem('wisp_aiw', String(w));
    set({ aiW: w });
  },
  bottomH: Number(localStorage.getItem('wisp_bottom_h') ?? 230),
  setBottomH: (h) => {
    localStorage.setItem('wisp_bottom_h', String(h));
    set({ bottomH: h });
  },
  toggleRail: () => {
    const next: Rail = get().rail === 'wide' ? 'narrow' : 'wide';
    localStorage.setItem('wisp_rail', next);
    set({ rail: next });
  },
  sessions: [],
  projects: [],
  tasks: [],
  jobs: [],
  events: [],
  selected: '',
  sseUp: false,
  error: '',
  shotReq: '',
  toasts: [],
  toast: (t) => {
    const id = Date.now() + Math.random();
    set({ toasts: [...get().toasts.slice(-4), { ...t, id }] });
    setTimeout(() => get().dismissToast(id), t.kind === 'err' ? 8000 : 4500);
  },
  dismissToast: (id) => set({ toasts: get().toasts.filter((x) => x.id !== id) }),
  reqShot: (id) => set({ shotReq: id }),
  clearShot: () => set({ shotReq: '' }),
  goalTick: 0,
  helpOpen: false,
  setHelpOpen: (v) => set({ helpOpen: v }),
  dynTabs: [],
  theme: ((localStorage.getItem('wispp-theme') as 'dark' | 'light') || 'light'),
  setTheme: (t) => { localStorage.setItem('wispp-theme', t); document.documentElement.dataset.theme = t; set({ theme: t }); },
  toggleTheme: () => { const nx = get().theme === 'dark' ? 'light' : 'dark'; get().setTheme(nx); },
  activeTab: 'console',
  openTab: (kind, session) => {
    const id = kind === 'payload' ? kind : `${kind}:${session ?? ''}`;
    const { dynTabs } = get();
    if (!dynTabs.some((t) => t.id === id)) {
      set({ dynTabs: [...dynTabs, { id, kind, session }], activeTab: id });
    } else {
      set({ activeTab: id });
    }
  },
  closeTab: (id) => {
    const { dynTabs, activeTab } = get();
    const left = dynTabs.filter((t) => t.id !== id);
    set({ dynTabs: left, activeTab: activeTab === id ? 'console' : activeTab });
  },
  setActiveTab: (id) => set({ activeTab: id }),

  setToken: (t) => {
    localStorage.setItem('wisp_token', t);
    set({ token: t, error: '' });
    get().refresh().catch((e) => set({ error: String(e) }));
    get().connectSSE();
  },

  setSelected: (id) => set({ selected: id }),

  refresh: async () => {
    const p = get().project;
    const q = p ? `?project=${encodeURIComponent(p)}` : '';
    const [sr, tr, lr, jr, pr] = await Promise.all([
      api('/api/sessions'), api(`/api/tasks${q}`), api(`/api/logs${q}`), api(`/api/files${q}`),
      api('/api/projects'),
    ]);
    if (sr.status === 401) {
      localStorage.removeItem('wisp_token');
      set({ token: '', sessions: [], projects: [], tasks: [], events: [], error: useI18n.getState().t('errBadToken') });
      return;
    }
    if (!sr.ok || !tr.ok || !lr.ok) throw new Error(`api ${sr.status}/${tr.status}/${lr.status}`);
    const [s, t, l, j, pj] = [await sr.json(), await tr.json(), await lr.json(), await jr.json(), await pr.json()] as [Session[], TaskRecord[], TeamEvent[], FileJob[], Project[]];
    set({
      sessions: Array.isArray(s) ? s : [],
      projects: Array.isArray(pj) ? pj : [],
      tasks: (Array.isArray(t) ? t : []).sort((a, b) => b.task.created - a.task.created),
      jobs: Array.isArray(j) ? j : [],
      events: Array.isArray(l) ? l : [],
      error: '',
    });
    const { selected, project } = get();
    const inProj = (x: Session) => !project || x.project === project;
    if ((!selected || !s.some((x) => x.id === selected && inProj(x))) && s.length) {
      const first = s.find(inProj) ?? s[0];
      if (first) set({ selected: first.id });
    }
  },

  connectSSE: () => {
    const tok = localStorage.getItem('wisp_token') ?? '';
    const es = new EventSource(`/api/events?token=${encodeURIComponent(tok)}`);
    es.onopen = () => set({ sseUp: true });
    es.onerror = () => {
      set({ sseUp: false });
      es.close();
      setTimeout(() => get().connectSSE(), 3000);
    };
    es.onmessage = (m) => {
      try {
        const ev = JSON.parse(m.data) as TeamEvent;
        const { events } = get();
        set({ events: [...events.slice(-499), ev] });
        if (ev.kind === 'session' || ev.kind === 'task' || ev.kind === 'file' || ev.kind === 'goal') get().refresh().catch(() => {});
        if (ev.kind === 'goal') set({ goalTick: get().goalTick + 1 });
        // human-facing notifications (deduped by content)
        if (ev.kind === 'session' && ev.level === 'ok' && ev.text.includes('new agent')) {
          get().toast({ kind: 'ok', text: `${useI18n.getState().t('newSessToast')}${ev.text.replace('new agent ', '').slice(0, 40)}` });
        } else if (ev.kind === 'file' && ev.text.includes('-> done')) {
          get().toast({ kind: 'ok', text: `📁 ${ev.text.slice(0, 46)}` });
        } else if (ev.kind === 'security' && ev.level === 'err') {
          get().toast({ kind: 'err', text: `🛡 ${ev.text.slice(0, 60)}` });
        }
      } catch {
        /* ignore malformed frame */
      }
    };
  },

  runTask: async (session, cmd, args, timeoutMs = 25000) => {
    const r = await api(`/api/sessions/${session}/tasks`, {
      method: 'POST',
      body: JSON.stringify({ cmd, args }),
    });
    if (!r.ok) throw new Error(`dispatch ${r.status}`);
    const rec = (await r.json()) as TaskRecord;
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      await new Promise((res) => setTimeout(res, 500));
      const list = await api(`/api/tasks?session=${session}`).then((x) => x.json()) as TaskRecord[];
      const cur = list.find((t) => t.task.id === rec.task.id);
      if (cur && (cur.status === 'completed' || cur.status === 'failed')) return cur;
      if (Date.now() > deadline) throw new Error(`task ${rec.task.id} timeout (sleep+jitter)`);
    }
  },

  dispatch: async (session, cmd, args) => {
    const r = await api(`/api/sessions/${session}/tasks`, {
      method: 'POST',
      body: JSON.stringify({ cmd, args }),
    });
    if (!r.ok) throw new Error(`dispatch ${r.status}: ${await r.text()}`);
    await get().refresh();
  },
}));

document.documentElement.dataset.theme = useStore.getState().theme;
