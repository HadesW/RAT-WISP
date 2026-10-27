// Cmd+K command palette: sessions, tabs, actions — one keyboard-first entry.
import { useEffect, useMemo, useRef, useState } from 'react';
import { useStore } from './store';
import { useI18n } from './i18n';
import { Api } from './api';

interface Cmd { id: string; label: string; hint?: string; run: () => void; }

export function CmdPalette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [q, setQ] = useState('');
  const [sel, setSel] = useState(0);
  const input = useRef<HTMLInputElement>(null);
  const sessions = useStore((s) => s.sessions);
  const setView = useStore((s) => s.setView);

  useEffect(() => {
    if (open) { setQ(''); setSel(0); setTimeout(() => input.current?.focus(), 20); }
  }, [open]);

  const cmds = useMemo<Cmd[]>(() => {
    const st = useStore.getState();
    const tr = useI18n.getState().t;
    const { t: _unused } = useI18n.getState(); void _unused;
    const open = tr('mOpenShell').includes('Open') ? 'Open' : '打开';
    const tabW = tr('tabHintWord') || 'tab';
    const base: Cmd[] = [
      { id: 't-lsn', label: open + ' ' + tr('tlsn'), hint: tabW, run: () => { setView('sessions'); st.openTab('lsn'); } },
      { id: 't-plugin', label: open + ' ' + tr('tplg'), hint: tabW, run: () => { setView('sessions'); st.openTab('plugin'); } },
      { id: 't-payload', label: open + ' ' + tr('tp'), hint: tabW, run: () => { setView('sessions'); st.openTab('payload'); } },
      { id: 't-report', label: open + ' ' + tr('trep'), hint: tabW, run: () => { setView('sessions'); st.openTab('report'); } },
      { id: 't-goal', label: open + ' ' + tr('tgoal'), hint: tabW, run: () => { setView('sessions'); st.openTab('goal'); } },
      { id: 't-fserver', label: open + ' ' + tr('tf'), hint: tabW, run: () => { setView('sessions'); st.openTab('fserver'); } },
      { id: 't-metrics', label: open + ' ' + tr('tmtr'), hint: tabW, run: () => { setView('sessions'); st.openTab('metrics'); } },
      { id: 't-loot', label: open + ' ' + tr('tloot'), hint: tabW, run: () => { setView('sessions'); st.openTab('loot'); } },
      { id: 'v-settings', label: open + ' ' + tr('gateTitle'), hint: tr('vendors'), run: () => useStore.getState().setModal('settings') },
      { id: 'r-rail', label: '⌥ ' + tr('sessions') + ' / ' + tr('ai'), hint: 'rail', run: () => st.toggleRail() },
      { id: 'r-lang', label: 'lang 中/EN', run: () => useI18n.getState().toggle() },
      { id: 'r-theme', label: '☀🌙 ' + tr('themeToggle'), run: () => useStore.getState().toggleTheme() },
      { id: 'r-ai', label: 'AI panel = 340px', run: () => st.setAIW(340) },
    ];
    for (const s of sessions) {
      base.push({
        id: `s-${s.id}`,
        label: `${tr('sessWord')} #${s.num} · ${s.info.hostname}`,
        hint: `${s.info.user}@${s.info.os} ${s.status}`,
        run: () => { setView('sessions'); st.setSelected(s.id); st.setActiveTab('console'); },
      });
      base.push({
        id: `rc-${s.id}`, label: '🖥 ' + tr('mRemote') + ` #${s.num}`, hint: s.info.hostname,
        run: () => window.open(`/rc/${s.id}?token=${encodeURIComponent(localStorage.getItem('wisp_token') ?? '')}`, '_blank'),
      });
      base.push({
        id: `sk-${s.id}`, label: '🌐 ' + tr('mSocks') + ` #${s.num}`, hint: 'SOCKS5',
        run: () => {
          void Api.socks.create(s.id)
            .then((d) => st.toast({ kind: 'ok', text: `🌐 SOCKS5 ${d.listen}` }))
            .catch((e) => st.toast({ kind: 'err', text: `⚠ ${e instanceof Error ? e.message : String(e)}` }));
        },
      });
      base.push({
        id: `fw-${s.id}`, label: '🔀 ' + tr('mFwdLbl') + ` #${s.num}`, hint: 'TCP',
        run: () => {
          const target = window.prompt(`→ ${s.info.hostname}`, '127.0.0.1:3389');
          if (!target) return;
          void Api.forwards.create(s.id, target)
            .then((d) => st.toast({ kind: 'ok', text: tr('fwdToast').replace('{a}', d.listen).replace('{b}', d.target) }))
            .catch((e) => st.toast({ kind: 'err', text: `⚠ ${e instanceof Error ? e.message : String(e)}` }));
        },
      });
    }
    const lq = q.toLowerCase();
    return lq ? base.filter((c) => (c.label + (c.hint ?? '')).toLowerCase().includes(lq)) : base;
  }, [q, sessions, setView]);

  useEffect(() => { setSel(0); }, [q]);
  if (!open) return null;
  const run = (c?: Cmd) => { if (c) { onClose(); c.run(); } };
  return (
    <div className="pal-mask" onMouseDown={onClose}>
      <div className="pal" onMouseDown={(e) => e.stopPropagation()}>
        <input
          ref={input}
          value={q}
          placeholder={useI18n.getState().t('palSearch')}
          onChange={(e) => setQ(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'ArrowDown') { e.preventDefault(); setSel((x) => Math.min(x + 1, cmds.length - 1)); }
            else if (e.key === 'ArrowUp') { e.preventDefault(); setSel((x) => Math.max(x - 1, 0)); }
            else if (e.key === 'Enter') run(cmds[sel]);
            else if (e.key === 'Escape') onClose();
          }}
        />
        <div className="pal-list">
          {cmds.map((c, i) => (
            <div key={c.id} className={`pal-item${i === sel ? ' on' : ''}`} onMouseEnter={() => setSel(i)} onClick={() => run(c)}>
              <span>{c.label}</span>
              {c.hint && <i>{c.hint}</i>}
            </div>
          ))}
          {!cmds.length && <div className="pal-item dis">{useI18n.getState().t('palNone')}</div>}
        </div>
      </div>
    </div>
  );
}

export function ToastHost() {
  const toasts = useStore((s) => s.toasts);
  const dismiss = useStore((s) => s.dismissToast);
  if (!toasts.length) return null;
  return (
    <div className="toast-host">
      {toasts.map((t) => (
        <div key={t.id} className={`toast ${t.kind}`} onClick={() => dismiss(t.id)}>
          <span>{t.text}</span>
          {t.action && (
            <button onClick={(e) => { e.stopPropagation(); t.action!.run(); dismiss(t.id); }}>{t.action.label}</button>
          )}
        </div>
      ))}
    </div>
  );
}
