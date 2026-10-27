import { useEffect, useMemo, useRef, useState } from 'react';
import { useI18n, tr } from '../../i18n';
import { useStore } from '../../store';
import { Api } from '../../api';
import { copy, fmtSize, shortTime } from '../../ui';
import type { FileJob, LsEntry, Session } from '../../types';

type FileSort = { k: 'name' | 'size' | 'mtime'; d: 1 | -1 };
type Hist = { stack: string[]; i: number };

// last browsed directory per session, restored when the session is re-selected
const lastPath = new Map<string, string>();

export default function FilesPanel({ session }: { session?: Session }) {
  const { t } = useI18n();
  const { runTask, jobs, error } = useStore();
  const [path, setPath] = useState('');
  const [rows, setRows] = useState<LsEntry[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const [sel, setSel] = useState<Set<string>>(() => new Set());
  const [anchor, setAnchor] = useState<string | null>(null);
  const [sort, setSort] = useState<FileSort>({ k: 'name', d: 1 });
  const [menu, setMenu] = useState<{ x: number; y: number; row: LsEntry | null } | null>(null);
  const [q, setQ] = useState('');
  const [hideDot, setHideDot] = useState(false);
  const [auto, setAuto] = useState(false);
  const [dragN, setDragN] = useState(0);
  const [hist, setHist] = useState<Hist>({ stack: [], i: -1 });
  const reqSeq = useRef(0);
  const listRef = useRef<HTMLDivElement>(null);
  const filePick = useRef<HTMLInputElement>(null);
  const filterRef = useRef<HTMLInputElement>(null);
  const busyRef = useRef(false);
  const seenJobs = useRef<Map<string, string>>(new Map());

  const win = /^[A-Za-z]:/.test(path) || path.includes('\\');
  const sep = win ? '\\' : '/';
  const join = (name: string) => (path ? (path.endsWith(sep) ? path + name : path + sep + name) : name);

  const parent = () => {
    const t0 = path.replace(/[\\/]+$/, '');
    if (!t0) return path;
    if (/^[A-Za-z]:$/.test(t0)) return t0 + '\\';
    const i = Math.max(t0.lastIndexOf('\\'), t0.lastIndexOf('/'));
    if (i < 0) return path;
    if (i === 0) return '/';
    if (/^[A-Za-z]:/.test(t0) && i === 2) return t0.slice(0, 3);
    return t0.slice(0, i);
  };
  const upPath = parent();
  const atRoot = upPath === path;

  const crumbs = useMemo(() => {
    if (!path) return [] as { label: string; path: string }[];
    if (win) {
      const parts = path.split(/\\+/);
      const root = (parts[0] || '\\') + '\\';
      const out = [{ label: parts[0] || '\\', path: root }];
      let acc = parts[0] || '';
      for (const p of parts.slice(1)) {
        if (!p) continue;
        acc += '\\' + p;
        out.push({ label: p, path: acc });
      }
      return out;
    }
    const out = [{ label: '/', path: '/' }];
    let acc = '';
    for (const p of path.split(/\/+/)) {
      if (!p) continue;
      acc += '/' + p;
      out.push({ label: p, path: acc });
    }
    return out;
  }, [path, win]);

  const sorted = useMemo(() => {
    const a = [...(rows ?? [])];
    a.sort((x, y) => {
      if (x.dir !== y.dir) return x.dir ? -1 : 1;
      let c = 0;
      if (sort.k === 'name') c = x.name.localeCompare(y.name, undefined, { numeric: true, sensitivity: 'base' });
      else if (sort.k === 'size') c = x.size - y.size;
      else c = x.mtime - y.mtime;
      if (c === 0) c = x.name.localeCompare(y.name);
      return c * sort.d;
    });
    return a;
  }, [rows, sort]);

  const view = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return sorted.filter(
      (r) => (!hideDot || !r.name.startsWith('.')) && (!needle || r.name.toLowerCase().includes(needle)),
    );
  }, [sorted, q, hideDot]);
  const selected = view.filter((r) => sel.has(r.name));
  const selBytes = selected.reduce((a, r) => a + (r.dir ? 0 : r.size), 0);

  // mode: push — record a history entry (user navigation); none — silent
  // refresh / history jump that must not grow or shift the stack.
  const ls = async (p: string, mode: 'push' | 'none' = 'push'): Promise<boolean> => {
    if (!session) return false;
    const id = ++reqSeq.current;
    setBusy(true);
    busyRef.current = true;
    setErr('');
    try {
      const task = await runTask(session.id, 'ls', { path: p });
      if (id !== reqSeq.current) return false;
      if (task.status !== 'completed' || !task.result?.output) throw new Error(task.result?.output ?? 'ls failed');
      const d = JSON.parse(task.result.output) as { path: string; entries: LsEntry[] };
      // same directory (refresh) → keep selection, pruned to surviving names
      const sameDir = d.path === path;
      setPath(d.path);
      setRows(d.entries);
      lastPath.set(session.id, d.path);
      if (sameDir) {
        const names = new Set(d.entries.map((x) => x.name));
        setSel((prev) => new Set([...prev].filter((n) => names.has(n))));
        setAnchor((a) => (a && names.has(a) ? a : null));
      } else {
        setSel(new Set());
        setAnchor(null);
      }
      if (mode === 'push') {
        setHist((h) => {
          if (h.stack[h.i] === d.path) return h;
          const stack = [...h.stack.slice(0, h.i + 1), d.path];
          return { stack, i: stack.length - 1 };
        });
      }
      return true;
    } catch (e) {
      if (id === reqSeq.current) setErr(String(e));
      return false;
    } finally {
      if (id === reqSeq.current) {
        setBusy(false);
        busyRef.current = false;
      }
    }
  };

  const goBack = async () => {
    if (hist.i <= 0) return;
    if (await ls(hist.stack[hist.i - 1], 'none')) setHist((h) => ({ ...h, i: h.i - 1 }));
  };
  const goFwd = async () => {
    if (hist.i < 0 || hist.i >= hist.stack.length - 1) return;
    if (await ls(hist.stack[hist.i + 1], 'none')) setHist((h) => ({ ...h, i: h.i + 1 }));
  };

  useEffect(() => {
    setRows(null);
    setPath('');
    setSel(new Set());
    setAnchor(null);
    setQ('');
    setHist({ stack: [], i: -1 });
    if (!session) return;
    // restore this session's last directory; fall back to root if it vanished
    void (async () => {
      const start = lastPath.get(session.id) ?? '';
      if (start && (await ls(start))) return;
      await ls('');
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session?.id]);

  // silent refresh while the listing is idle: manual toggle, or a transfer
  // job for this session completing (the new file should show up).
  useEffect(() => {
    if (!auto || !session) return;
    const id = window.setInterval(() => {
      if (!busyRef.current) void ls(path, 'none');
    }, 5000);
    return () => window.clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [auto, session?.id, path]);

  useEffect(() => {
    if (!session) return;
    let done = false;
    const next = new Map<string, string>();
    for (const j of jobs) {
      if (j.agent !== session.id) continue;
      next.set(j.id, j.status);
      const prev = seenJobs.current.get(j.id);
      if (prev && prev !== 'done' && j.status === 'done') done = true;
    }
    seenJobs.current = next;
    if (done && !busyRef.current) void ls(path, 'none');
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [jobs, session?.id]);

  const grab = (remote: string) => {
    if (!session) return;
    void Api.files.grab(session.id, remote)
      .catch((e) => useStore.setState({ error: e instanceof Error ? e.message : String(e) }));
  };

  const rmMany = async (targets: LsEntry[]) => {
    if (!session || !targets.length) return;
    const q0 = targets.length === 1
      ? t('confirmRm').replace('{p}', join(targets[0].name))
      : t('confirmRmN').replace('{n}', String(targets.length));
    if (!confirm(q0)) return;
    try {
      for (const r of targets) await runTask(session.id, 'rm', { path: join(r.name) });
    } catch (e) {
      setErr(String(e));
    }
    await ls(path, 'none');
  };

  const mkdir = async () => {
    if (!session) return;
    const name = prompt(t('newFolderPh'), t('newFolderDefault'));
    if (!name?.trim()) return;
    try {
      await runTask(session.id, 'mkdir', { path: join(name.trim()) });
      await ls(path, 'none');
    } catch (e) {
      setErr(String(e));
    }
  };

  const uploadOne = async (f: File) => {
    if (!session) return;
    const dst = join(f.name);
    if (rows?.some((r) => r.name === f.name && !r.dir) && !confirm(t('confirmOverwrite').replace('{p}', dst))) return;
    const up = await Api.files.upload(f.name, f);
    await Api.files.push(session.id, dst, up.inbox);
  };

  const pickFiles = async (files: File[]) => {
    if (!files.length) return;
    setBusy(true);
    busyRef.current = true;
    setErr('');
    let failed = '';
    try {
      for (const f of files) await uploadOne(f);
    } catch (e) {
      failed = String(e);
    }
    setBusy(false);
    busyRef.current = false;
    if (failed) setErr(failed);
    else await ls(path, 'none');
  };

  const onPick = (files: FileList | null) => {
    if (files?.length) void pickFiles(Array.from(files));
  };

  useEffect(() => {
    if (!menu) return;
    const close = () => setMenu(null);
    const esc = (e: KeyboardEvent) => { if (e.key === 'Escape') setMenu(null); };
    window.addEventListener('mousedown', close);
    window.addEventListener('keydown', esc);
    return () => { window.removeEventListener('mousedown', close); window.removeEventListener('keydown', esc); };
  }, [menu]);

  const clickRow = (e: React.MouseEvent, r: LsEntry, idx: number) => {
    if (e.shiftKey && anchor) {
      const ai = view.findIndex((x) => x.name === anchor);
      if (ai >= 0) {
        const [lo, hi] = ai < idx ? [ai, idx] : [idx, ai];
        setSel(new Set(view.slice(lo, hi + 1).map((x) => x.name)));
        return;
      }
    }
    if (e.ctrlKey || e.metaKey) {
      const n = new Set(sel);
      if (n.has(r.name)) n.delete(r.name);
      else n.add(r.name);
      setSel(n);
      setAnchor(r.name);
      return;
    }
    setSel(new Set([r.name]));
    setAnchor(r.name);
  };

  const focusRow = (r: LsEntry) => {
    setSel(new Set([r.name]));
    setAnchor(r.name);
    requestAnimationFrame(() => {
      listRef.current?.querySelector(`[data-row="${CSS.escape(r.name)}"]`)?.scrollIntoView({ block: 'nearest' });
    });
  };

  const moveSel = (delta: number) => {
    if (!view.length) return;
    const cur = view.findIndex((r) => r.name === anchor);
    const next = Math.max(0, Math.min(view.length - 1, cur < 0 ? 0 : cur + delta));
    focusRow(view[next]);
  };

  const openRow = (r: LsEntry) => {
    if (r.dir) void ls(join(r.name));
    else grab(join(r.name));
  };

  const onKey = (e: React.KeyboardEvent) => {
    const tag = (e.target as HTMLElement).tagName;
    if (tag === 'INPUT' || tag === 'TEXTAREA') return;
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'a') {
      e.preventDefault();
      setSel(new Set(view.map((r) => r.name)));
      return;
    }
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'f') {
      e.preventDefault();
      filterRef.current?.focus();
      filterRef.current?.select();
      return;
    }
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'c') {
      if (selected.length) {
        e.preventDefault();
        void copy(selected.map((r) => join(r.name)).join('\n'));
      }
      return;
    }
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'r') {
      e.preventDefault();
      void ls(path, 'none');
      return;
    }
    if (e.altKey && e.key === 'ArrowLeft') { e.preventDefault(); void goBack(); return; }
    if (e.altKey && e.key === 'ArrowRight') { e.preventDefault(); void goFwd(); return; }
    switch (e.key) {
      case 'ArrowDown': e.preventDefault(); moveSel(1); break;
      case 'ArrowUp': e.preventDefault(); moveSel(-1); break;
      case 'PageDown': e.preventDefault(); moveSel(10); break;
      case 'PageUp': e.preventDefault(); moveSel(-10); break;
      case 'Home': e.preventDefault(); if (view.length) focusRow(view[0]); break;
      case 'End': e.preventDefault(); if (view.length) focusRow(view[view.length - 1]); break;
      case 'Enter': e.preventDefault(); if (selected.length === 1) openRow(selected[0]); break;
      case 'Backspace': e.preventDefault(); if (!atRoot) void ls(upPath); break;
      case 'Delete': e.preventDefault(); void rmMany(selected); break;
      case 'F5': e.preventDefault(); void ls(path, 'none'); break;
      case 'Escape':
        if (q) setQ('');
        else { setSel(new Set()); setAnchor(null); }
        break;
    }
  };

  const sortBy = (k: FileSort['k']) => setSort((s) => ({ k, d: s.k === k ? (s.d === 1 ? -1 : 1) : 1 }));
  const arrow = (k: FileSort['k']) => (sort.k === k ? (sort.d === 1 ? ' ▲' : ' ▼') : '');

  const filtered = Boolean(q.trim()) || hideDot;
  const summary = selected.length > 1
    ? t('fSelSum').replace('{n}', String(selected.length)).replace('{s}', fmtSize(selBytes))
    : selected.length === 1
      ? `${join(selected[0].name)} · ${selected[0].dir ? '—' : `${selected[0].size.toLocaleString()} B`} · ${new Date(selected[0].mtime * 1000).toLocaleString()}`
      : filtered
        ? `${view.length} / ${rows?.length ?? 0} ${t('itemsWord')}`
        : `${rows?.length ?? 0} ${t('itemsWord')}`;

  const onDragFiles = (types: readonly string[]) => types.includes('Files');

  const myJobs = jobs.filter((j) => j.agent === session?.id).slice(0, 6);
  if (!session) return <div className="console"><div className="c-out muted">{tr("pickSessFiles")}</div></div>;
  return (
    <div className="panel-file" tabIndex={0} onKeyDown={onKey}
      onDragOver={(e) => {
        if (!onDragFiles(e.dataTransfer.types)) return;
        e.preventDefault();
        e.dataTransfer.dropEffect = 'copy';
      }}
      onDragEnter={(e) => { if (onDragFiles(e.dataTransfer.types)) { e.preventDefault(); setDragN((n) => n + 1); } }}
      onDragLeave={() => setDragN((n) => Math.max(0, n - 1))}
      onDrop={(e) => {
        const fs = e.dataTransfer.files;
        setDragN(0);
        if (!fs?.length) return;
        e.preventDefault();
        void pickFiles(Array.from(fs));
      }}>
      <div className="file-bar">
        <button disabled={busy || hist.i <= 0} onClick={() => void goBack()} title={`${t('fileBack')} · Alt+←`}>◀</button>
        <button disabled={busy || hist.i < 0 || hist.i >= hist.stack.length - 1} onClick={() => void goFwd()} title={`${t('fileFwd')} · Alt+→`}>▶</button>
        <button disabled={busy || atRoot} onClick={() => void ls(upPath)} title={t('upDir')}>⬑</button>
        <button disabled={busy} onClick={() => void ls(path, 'none')} title={`${t('refreshW')} · F5`}>↻</button>
        <input value={path} spellCheck={false} list="file-hist" onChange={(e) => setPath(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); void ls(path); } }} />
        <datalist id="file-hist">{hist.stack.map((p, i) => <option key={p + i} value={p} />)}</datalist>
        <input ref={filterRef} className="f-filter" value={q} spellCheck={false} placeholder={t('fFilterPh')}
          onChange={(e) => setQ(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Escape') { e.stopPropagation(); setQ(''); }
            if (e.key === 'Enter' && view.length) { e.preventDefault(); focusRow(view[0]); }
          }} />
        {selected.length > 0 && <>
          <button onClick={() => selected.forEach((r) => { if (!r.dir) grab(join(r.name)); })} title={t('grabSel')}>⬇ {selected.length}</button>
          <button className="danger" onClick={() => void rmMany(selected)} title={t('delWord')}>✕ {selected.length}</button>
        </>}
        <button disabled={busy} onClick={() => void mkdir()} title={t('newFolder')}>＋</button>
        <button disabled={busy} onClick={() => filePick.current?.click()} title={t('uploadHere')}>⇧ {t('uploadWord')}</button>
        <input ref={filePick} type="file" multiple style={{ display: 'none' }}
          onChange={(e) => { onPick(e.target.files); e.target.value = ''; }} />
        <button className={auto ? 'on' : ''} onClick={() => setAuto((v) => !v)} title={t('fAuto')}>⏱</button>
        <button className={hideDot ? 'on' : ''} onClick={() => setHideDot((v) => !v)} title={t('fHidden')}>.*</button>
        <span className="file-status" title={err || path}>
          {busy ? t('busyWord') : err ? `⚠ ${err}` : ''}
        </span>
      </div>
      <div className="file-crumbs">
        <button className="crumb-btn" onClick={() => void ls('')} title={t('fileRoot')}>⌂</button>
        {crumbs.map((c, i) => (
          <span className="crumb-seg" key={c.path + i}>
            {i > 0 && <span className="crumb-sep">›</span>}
            <button className="crumb-btn" onClick={() => void ls(c.path)} title={c.path}>{c.label}</button>
          </span>
        ))}
      </div>
      <div className="file-hd">
        <span className={sort.k === 'name' ? 'on' : ''} onClick={() => sortBy('name')}>{t('fName')}{arrow('name')}</span>
        <span className={sort.k === 'size' ? 'on' : ''} onClick={() => sortBy('size')}>{t('fSize')}{arrow('size')}</span>
        <span className={sort.k === 'mtime' ? 'on' : ''} onClick={() => sortBy('mtime')}>{t('fMtime')}{arrow('mtime')}</span>
        <span />
      </div>
      <div className="file-list" ref={listRef}
        onClick={(e) => { if (e.target === e.currentTarget) { setSel(new Set()); setAnchor(null); } }}
        onContextMenu={(e) => {
          if (e.target !== e.currentTarget) return;
          e.preventDefault();
          setSel(new Set());
          setMenu({ x: e.clientX, y: e.clientY, row: null });
        }}>
        {!atRoot && (
          <div className="file-row file-up" onDoubleClick={() => void ls(upPath)} onClick={() => setSel(new Set())} title={t('upDir')}>
            <span className="fr-name">⬑ ..</span><span className="fr-size">—</span><span className="fr-mt" /><span />
          </div>
        )}
        {view.map((r, idx) => (
          <div key={r.name} data-row={r.name}
            className={`file-row${sel.has(r.name) ? ' sel' : ''}${anchor === r.name ? ' active' : ''}`}
            onClick={(e) => clickRow(e, r, idx)}
            onDoubleClick={() => openRow(r)}
            onContextMenu={(e) => {
              e.preventDefault();
              if (!sel.has(r.name)) { setSel(new Set([r.name])); setAnchor(r.name); }
              setMenu({ x: e.clientX, y: e.clientY, row: r });
            }}>
            <span className="fr-name" title={join(r.name)}>{r.dir ? '📁' : '📄'} {r.name}</span>
            <span className="fr-size" title={r.dir ? '' : `${r.size.toLocaleString()} B`}>{r.dir ? '—' : fmtSize(r.size)}</span>
            <span className="fr-mt" title={new Date(r.mtime * 1000).toLocaleString()}>{shortTime(r.mtime)}</span>
            <span className="fr-acts">
              {!r.dir && <button title={t('grabFile')} onClick={(e) => { e.stopPropagation(); grab(join(r.name)); }}>⬇</button>}
              <button title={t('delWord')} className="danger" onClick={(e) => { e.stopPropagation(); void rmMany([r]); }}>✕</button>
            </span>
          </div>
        ))}
        {rows && !view.length && !busy && (
          <div className="empty">
            {(q || hideDot) ? t('fNoMatch') : t('emptyWord')}
            {q && <div><button onClick={() => setQ('')}>✕ {t('fFilterPh')}</button></div>}
          </div>
        )}
        {!rows && busy && <div className="file-loading">{t('fLoading')}</div>}
        {!rows && !busy && (
          <div className="empty">
            {err
              ? <>
                  <div className="fe-err">⚠ {err}</div>
                  <div><button onClick={() => void ls(path)}>{t('retryWord')}</button></div>
                </>
              : t('emptyWord')}
          </div>
        )}
      </div>
      <div className="file-foot">
        <span className="ff-detail" title={summary}>{summary}</span>
        <span className="ff-hint">{t('fKeys')}</span>
      </div>
      {myJobs.length > 0 && (
        <div className="job-q">
          {myJobs.map((j) => <JobRow key={j.id} j={j} />)}
        </div>
      )}
      {error && !myJobs.length && <div className="job-q"><span className="job-err">{error}</span></div>}
      {dragN > 0 && (
        <div className="file-drop">{t('fDrop').replace('{p}', path || '/')}</div>
      )}
      {menu && (
        <div className="ctx-menu" style={{ left: Math.min(menu.x, window.innerWidth - 220), top: Math.min(menu.y, window.innerHeight - 260) }}
          onMouseDown={(e) => e.stopPropagation()} onContextMenu={(e) => e.preventDefault()}>
          {menu.row && (menu.row.dir
            ? <div className="ctx-item" onClick={() => { const r = menu.row!; setMenu(null); void ls(join(r.name)); }}><span className="ctx-ico">▸</span><span className="ctx-lbl">{t('ctxOpen')}</span></div>
            : <div className="ctx-item" onClick={() => { const r = menu.row!; setMenu(null); grab(join(r.name)); }}><span className="ctx-ico">⬇</span><span className="ctx-lbl">{t('ctxDownload')}</span></div>)}
          {menu.row && <div className="ctx-item" onClick={() => { const r = menu.row!; setMenu(null); void copy(join(r.name)); }}><span className="ctx-ico">⧉</span><span className="ctx-lbl">{t('ctxCopyPath')}</span></div>}
          {menu.row && <div className="ctx-item" onClick={() => { const r = menu.row!; setMenu(null); void copy(r.name); }}><span className="ctx-ico">ａ</span><span className="ctx-lbl">{t('ctxCopyName')}</span></div>}
          {!menu.row && view.length > 0 && (
            <div className="ctx-item" onClick={() => { setMenu(null); setSel(new Set(view.map((r) => r.name))); }}><span className="ctx-ico">☑</span><span className="ctx-lbl">{t('fSelAll')}</span></div>
          )}
          <div className="ctx-sep" />
          <div className="ctx-item" onClick={() => { setMenu(null); filePick.current?.click(); }}><span className="ctx-ico">⇧</span><span className="ctx-lbl">{t('ctxUpload')}</span></div>
          <div className="ctx-item" onClick={() => { setMenu(null); void mkdir(); }}><span className="ctx-ico">＋</span><span className="ctx-lbl">{t('ctxNewFolder')}</span></div>
          <div className="ctx-item" onClick={() => { setMenu(null); void ls(path, 'none'); }}><span className="ctx-ico">↻</span><span className="ctx-lbl">{t('ctxRefresh')}</span></div>
          {menu.row && <>
            <div className="ctx-sep" />
            <div className="ctx-item danger" onClick={() => {
              const r = menu.row!;
              const targets = sel.has(r.name) && sel.size > 1 ? selected : [r];
              setMenu(null);
              void rmMany(targets);
            }}><span className="ctx-ico">⌫</span><span className="ctx-lbl">{t('ctxDelete')}</span></div>
          </>}
        </div>
      )}
    </div>
  );
}

function JobRow({ j }: { j: FileJob }) {
  const pct = j.size ? Math.min(100, Math.round((j.received * j.chunk * 100) / j.size)) : 0;
  const retry = () => void Api.files.retry(j.id);
  return (
    <div className="job-row" title={`${j.remote} · sha ${j.sha256.slice(0, 12)}`}>
      <span>{j.mode === 'up' ? `⬇${tr('grabWord')}` : `⬆${tr('pushWord')}`}</span>
      <span className="jr-name">{j.remote.split(/[\\/]/).pop() || j.remote}</span>
      <span className="jr-bar"><i style={{ width: `${j.status === 'done' ? 100 : pct}%` }} /></span>
      <span className={`jr-st st-${j.status}`}>{j.status === 'done' ? tr('jobDone') : j.status === 'failed' ? tr('jobResume') : j.status === 'active' ? `${pct}%` : tr('jobQueued')}</span>
      {j.status === 'failed' && <button onClick={retry}>{tr("resumeWord")}</button>}
      {j.mode === 'up' && j.status === 'done' && (
        <button onClick={() => window.open(Api.files.downloadUrl(j.id), '_blank')}>{tr("saveToFile")}</button>
      )}
    </div>
  );
}
