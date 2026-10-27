// Small shared UI helpers (time humanization, clipboard).

import { useI18n } from './i18n';

export function ago(iso: string): string {
  const { t } = useI18n.getState();
  const sec = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000));
  if (sec < 3) return t('justNow');
  if (sec < 60) return `${sec}${t('secAgo')}`;
  if (sec < 3600) return `${Math.floor(sec / 60)}${t('minAgo')}`;
  if (sec < 86400) return `${Math.floor(sec / 3600)}${t('hourAgo')}`;
  return `${Math.floor(sec / 86400)}${t('dayAgo')}`;
}

export function shortTime(unix: number): string {
  const d = new Date(unix * 1000);
  const p = (n: number) => String(n).padStart(2, '0');
  return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

export function fullTime(iso: string): string {
  return new Date(iso).toLocaleString();
}

export async function copy(text: string, label = useI18n.getState().t('copiedWord')): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.append(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
  }
  const { useStore } = await import('./store');
  useStore.getState().toast({ kind: 'ok', text: `${label}: ${text.slice(0, 40)}` });
}

export function fmtSize(n: number): string {
  if (!n) return '—';
  const u = ['B', 'KB', 'MB', 'GB'];
  let i = 0;
  while (n >= 1024 && i < 3) { n /= 1024; i++; }
  return `${n.toFixed(n >= 100 || i === 0 ? 0 : 1)} ${u[i]}`;
}
