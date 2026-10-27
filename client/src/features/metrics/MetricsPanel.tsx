import { useEffect, useState } from 'react';
import { useI18n } from '../../i18n';
import { useStore } from '../../store';
import { Api } from '../../api';
import { fmtSize } from '../../ui';
import type { ListenerRow, Metrics } from '../../types';

const uptime = (s: number) => {
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${m}m`;
  return `${m}m ${s % 60}s`;
};

export default function MetricsPanel() {
  const { t } = useI18n();
  const project = useStore((s) => s.project);
  const [m, setM] = useState<Metrics | null>(null);
  const [lsns, setLsns] = useState<ListenerRow[]>([]);

  useEffect(() => {
    let stop = false;
    const load = async () => {
      try {
        const [x, l] = await Promise.all([Api.metrics(), Api.listeners.list()]);
        if (stop) return;
        setM(x);
        setLsns(l.filter((v) => !project || v.project === project));
      } catch { /* server down */ }
    };
    void load();
    const iv = setInterval(load, 5000);
    return () => { stop = true; clearInterval(iv); };
  }, [project]);

  if (!m) return <div className="metrics-wrap"><div className="empty">{t('mtrEmpty')}</div></div>;

  const cards = [
    { k: t('mtrSessions'), v: `${m.sessions_online}/${m.sessions_total}`, s: `${t('mtrIdle')} ${m.sessions_idle} · ${t('mtrOffline')} ${m.sessions_offline}`, ok: m.sessions_online > 0 },
    { k: t('mtrTasks'), v: String(m.tasks_pending + m.tasks_sent), s: `${t('mtrDone')} ${m.tasks_completed} · ${t('mtrFailed')} ${m.tasks_failed}` },
    { k: t('mtrJobs'), v: String(m.jobs_active), s: `${t('mtrDone')} ${m.jobs_done} · ${t('mtrFailed')} ${m.jobs_failed}` },
    { k: t('mtrListeners'), v: `${m.listeners_running}/${m.listeners_total}`, s: t('mtrRunning'), ok: m.listeners_running > 0 },
    { k: t('mtrType2'), v: String(m.rcp_online), s: t('mtrOnline'), ok: m.rcp_online > 0 },
    { k: t('mtrStage'), v: String(m.stage_active), s: t('mtrActive') },
    { k: t('mtrRuntime'), v: fmtSize(m.heap_alloc), s: `${m.goroutines} ${t('mtrGoroutines')} · ${uptime(m.uptime_sec)}` },
  ];

  return (
    <div className="metrics-wrap">
      <div className="mtr-grid">
        {cards.map((c) => (
          <div className="mtr-card" key={c.k}>
            <span className="mtr-k">{c.k}</span>
            <span className={`mtr-v${c.ok ? ' ok' : ''}`}>{c.v}</span>
            <span className="mtr-sub">{c.s}</span>
          </div>
        ))}
      </div>
      <div className="mtr-sec">
        <h4>{t('mtrListenerStats')}</h4>
        <table className="lsn-t">
          <thead><tr>
            <th>{t('thName')}</th><th>{t('thKind')}</th><th>{t('thOnline')}</th>
            <th>{t('mtrReq')}</th><th>{t('mtrIn')}</th><th>{t('mtrOut')}</th><th>{t('mtrErr')}</th>
          </tr></thead>
          <tbody>
            {lsns.map((l) => (
              <tr key={l.id}>
                <td>{l.name || l.id}</td>
                <td className="mono">{l.kind}</td>
                <td>{l.agents}</td>
                <td>{l.stats?.requests ?? '—'}</td>
                <td>{l.stats ? fmtSize(l.stats.bytes_in) : '—'}</td>
                <td>{l.stats ? fmtSize(l.stats.bytes_out) : '—'}</td>
                <td className={l.stats?.errors ? 'c-warn' : ''}>{l.stats?.errors ?? '—'}</td>
              </tr>
            ))}
            {!lsns.length && <tr><td colSpan={7} className="empty">{t('mtrEmpty')}</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
}