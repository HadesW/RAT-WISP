import { useEffect, useRef, useState, type ChangeEvent } from 'react';
import { useI18n, tr } from '../../i18n';
import { useStore } from '../../store';
import { Api } from '../../api';
import { fmtSize } from '../../ui';
import type { ForwardRow, ListenerRow as LSN, ProfileRow as ProfRow, SocksRow } from '../../types';


const PROFILE_TEMPLATE = JSON.stringify({
  name: 'my-profile',
  uris: ['/api/v1/{uuid}/events', '/health/{ts}'],
  method: 'POST',
  data: 'header:X-Request-Id',
  ua_pool: ['MyApp/2.1 (compatible; +https://example.com)', 'curl/8.4.0'],
  headers: [{ key: 'Accept', value: 'application/json' }, { key: 'User-Agent', value: '{ua}' }],
  response: { status: 200, content_type: 'application/json', body: '{"ok":true,"trace":"{data}"}' },
  not_found: { status: 404, content_type: 'application/json', body: '{"error":"not found"}' },
  sleep_ms: 5000, jitter_pct: 30,
}, null, 2);

// Kinds an operator creates here are Type1 agent-facing transports. RCP /
// RCP-KCP are the Type2 remote-desktop channel — server-side listeners created
// via API/deploy scripts, not a listener "protocol" (plan: RCP 不在监听器设置中).
const LSN_KINDS = [
  { kind: 'http', label: 'HTTP', port: 9000, hint: 'lsnKindHttp' },
  { kind: 'https', label: 'HTTPS', port: 9443, hint: 'lsnKindHttps' },
  { kind: 'tcp', label: 'TCP', port: 9100, hint: 'lsnKindTcp' },
  { kind: 'kcp', label: 'KCP', port: 9400, hint: 'lsnKindKcp' },
  { kind: 'quic', label: 'QUIC', port: 9080, hint: 'lsnKindQuic' },
];

export default function ListenerPanel({ onBack, asTab }: { onBack: () => void; asTab?: boolean }) {
  const { t, tf } = useI18n();
  const [sec, setSec] = useState<'lsn' | 'fwd' | 'socks' | 'prof'>('lsn');
  const sessions = useStore((st) => st.sessions);
  const project = useStore((st) => st.project);
  const [lsns, setLsns] = useState<LSN[]>([]);
  const [profs, setProfs] = useState<ProfRow[]>([]);
  const [kind, setKind] = useState('http');
  const [lname, setLname] = useState('');
  const [addr, setAddr] = useState('0.0.0.0:9000');
  const [lhost, setLhost] = useState('');
  const [prof, setProf] = useState('generic');
  const [msg, setMsg] = useState('');
  const [editLsn, setEditLsn] = useState<LSN | null>(null);
  const [detail, setDetail] = useState<LSN | null>(null);
  const [certOpen, setCertOpen] = useState(false);
  const [certPem, setCertPem] = useState('');
  const [keyPem, setKeyPem] = useState('');
  const [certMsg, setCertMsg] = useState('');
  const [certBusy, setCertBusy] = useState(false);
  const [lsnName, setLsnName] = useState('');
  const [lsnHost, setLsnHost] = useState('');
  const [fwds, setFwds] = useState<ForwardRow[]>([]);
  const [showHist, setShowHist] = useState(false);
  const [fSess, setFSess] = useState('');
  const [fTarget, setFTarget] = useState('127.0.0.1:3389');
  const [sks, setSks] = useState<SocksRow[]>([]);
  const [profName, setProfName] = useState('generic');
  const [editBody, setEditBody] = useState('');
  const [editNew, setEditNew] = useState(false);
  const [imp, setImp] = useState(false);
  const [impText, setImpText] = useState('');
  const ipsRef = useRef<string[]>([]);
  const ipIdx = useRef(0);

  const load = async () => {
    try {
      const [a, b, c, d] = await Promise.all([
        Api.listeners.list(), Api.profiles.list(), Api.forwards.list(), Api.socks.list(),
      ]);
      setLsns(a);
      setProfs(b);
      setFwds(c);
      setSks(d);
    } catch { /* server down */ }
  };
  useEffect(() => { void load(); const timer = setInterval(load, 4000); return () => clearInterval(timer); /* eslint-disable-next-line */ }, []);
  useEffect(() => {
    if (profs.length && !profs.some((p) => p.name === prof)) setProf(profs[0].name);
  }, [profs, prof]);
  useEffect(() => {
    if (editNew) return;
    const p = profs.find((x) => x.name === profName);
    if (p) setEditBody(p.body);
  }, [profName, profs, editNew]);

  // quic also binds a profile: its register ack hands out profile sleep/jitter
  // and the sealed envelopes get pad_block padding (plan P6).
  const profKind = kind === 'http' || kind === 'https' || kind === 'quic';
  const scopedLsns = lsns.filter((l) => !project || l.project === project);
  const running = scopedLsns.filter((l) => l.running).length;
  const kindMeta = LSN_KINDS.find((k) => k.kind === kind) ?? LSN_KINDS[0];
  const wildcard = addr.trim().startsWith('0.0.0.0:') && !lhost.trim();
  const bindPort = Number((/:(\d+)$/.exec(addr.trim()) || [])[1] || 0);
  const portClash = !!bindPort && lsns.some((l) => {
    if (!l.running) return false;
    const p = Number((/:(\d+)$/.exec(l.addr) || [])[1] || 0);
    if (p !== bindPort) return false;
    return l.addr.startsWith('0.0.0.0:') || addr.trim().startsWith('0.0.0.0:') || l.addr === addr.trim();
  });

  const pickKind = (k: string) => {
    setKind(k);
    const preset = LSN_KINDS.find((x) => x.kind === k);
    if (preset) {
      setAddr((prev) => {
        const oldPorts = LSN_KINDS.map((x) => x.port);
        const m = /:(\d+)$/.exec(prev.trim());
        if (!prev.trim() || (m && oldPorts.includes(Number(m[1])))) return `0.0.0.0:${preset.port}`;
        return prev;
      });
    }
    if (k !== 'http' && k !== 'https' && k !== 'quic') setProf('');
  };

  const applyTpl = () => {
    pickKind('http');
    setAddr('0.0.0.0:8080');
    setLname('web-http');
    setLhost('');
    setProf('generic');
    setMsg(`ⓘ ${t('lsnTplHttpHint')}`);
  };

  const act = async (fn: () => Promise<unknown>) => {
    try {
      await fn();
      setMsg('');
    } catch (e) {
      setMsg(`⚠ ${e instanceof Error ? e.message : String(e)}`);
    }
    void load();
  };

  const create = async () => {
    const a = addr.trim();
    const h = lhost.trim();
    if (!/^[^\s:]+:\d{1,5}$/.test(a)) { setMsg(`⚠ ${t('lsnInvalidAddr')}`); return; }
    if (h && !/^[^\s:]+(:\d{1,5})?$/.test(h)) { setMsg(`⚠ ${t('lsnInvalidHost')}`); return; }
    try {
      const d = await Api.listeners.create({ name: lname.trim(), kind, addr: a, host: h, profile: profKind ? prof : '', project: project || 'default' });
      setMsg(`✓ ${t('lsnCreated')} · ${d.name ?? a}`);
      setLname('');
    } catch (e) {
      setMsg(`⚠ ${e instanceof Error ? e.message : String(e)}`);
      return;
    }
    void load();
  };

  const detectHost = async () => {
    const port = /:(\d+)$/.exec(addr.trim())?.[1];
    const loc = window.location.hostname;
    if (loc && loc !== '127.0.0.1' && loc !== 'localhost' && loc !== '::1') {
      setLhost(port ? `${loc}:${port}` : loc);
      setMsg('');
      return;
    }
    if (!ipsRef.current.length) {
      const r = await Api.net.ips().catch(() => ({ ips: [] as string[] }));
      ipsRef.current = r.ips;
    }
    const ips = ipsRef.current;
    if (!ips.length) { setMsg(`⚠ ${t('lsnAutoNone')}`); return; }
    const ip = ips[ipIdx.current % ips.length];
    ipIdx.current++;
    setLhost(port ? `${ip}:${port}` : ip);
    setMsg(ips.length > 1 ? `ⓘ ${t('lsnAutoCycle')} ${ip}` : '');
  };

  const copy = (text: string) => {
    void navigator.clipboard.writeText(text)
      .then(() => setMsg(`✓ ${t('lsnCopied')} ${text}`))
      .catch(() => {});
  };

  const openInBuilder = (id: string) => {
    localStorage.setItem('wisp_builder_listener', id);
    useStore.getState().openTab('payload');
  };

  const openEdit = (l: LSN) => { setEditLsn(l); setLsnName(l.name); setLsnHost(l.host); };
  const saveLsn = async () => {
    if (!editLsn) return;
    try {
      await Api.listeners.update(editLsn.id, { name: lsnName, host: lsnHost });
      setMsg(`✓ ${t('lsnEdited')}`);
      setEditLsn(null);
    } catch (e) {
      setMsg(`⚠ ${e instanceof Error ? e.message : String(e)}`);
      return;
    }
    void load();
  };

  const readPem = (set: (v: string) => void) => (e: ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    if (f) void f.text().then(set).catch(() => setCertMsg('⚠ read failed'));
  };

  const saveCert = async () => {
    if (!detail) return;
    setCertBusy(true); setCertMsg('');
    try {
      await Api.listeners.setCert(detail.id, certPem, keyPem);
      setCertOpen(false); setCertPem(''); setKeyPem('');
      useStore.getState().toast({ kind: 'ok', text: t('lsnCertSaved') });
      void load();
    } catch (e) {
      setCertMsg(e instanceof Error ? e.message : String(e));
    } finally {
      setCertBusy(false);
    }
  };

  const clearCert = async () => {
    if (!detail || !confirm(t('lsnCertConfirmClear'))) return;
    try {
      await Api.listeners.clearCert(detail.id);
      useStore.getState().toast({ kind: 'ok', text: t('lsnCertCleared') });
      void load();
    } catch (e) {
      useStore.getState().toast({ kind: 'err', text: `⚠ ${e instanceof Error ? e.message : String(e)}` });
    }
  };

  const addFwd = async () => {
    if (!fSess) { setMsg(t('needSession')); return; }
    try {
      const d = await Api.forwards.create(fSess, fTarget);
      setMsg(`✓ ${d.listen} → ${d.target}`);
      useStore.getState().toast({ kind: 'ok', text: tr('fwdToast', { a: d.listen, b: d.target }) });
    } catch (e) {
      setMsg(`⚠ ${e instanceof Error ? e.message : String(e)}`);
    }
    void load();
  };
  const addSocks = async () => {
    if (!fSess) { setMsg(t('needSession')); return; }
    try {
      const d = await Api.socks.create(fSess);
      setMsg(`✓ SOCKS5 ${d.listen}`);
      useStore.getState().toast({ kind: 'ok', text: `🌐 SOCKS5 ${d.listen}` });
    } catch (e) {
      setMsg(`⚠ ${e instanceof Error ? e.message : String(e)}`);
    }
    void load();
  };

  const lint = async () => {
    const r = await Api.profiles.validate(editBody);
    setMsg(r.ok ? tr('lintOk') : `⚠ ${r.error}`);
  };
  const saveProf = async () => {
    const name = editNew ? (prompt(t('newProfPh'), 'my-profile') || '') : profName;
    if (!name) return;
    try {
      await Api.profiles.save(name, editBody);
      setProfName(name);
      setEditNew(false);
      setMsg(tr('profSavedN', { name }));
    } catch (e) {
      setMsg(`⚠ ${e instanceof Error ? e.message : String(e)}`);
    }
    void load();
  };
  const doImport = async () => {
    try {
      const r = await Api.profiles.importProfile(profName || 'imported', impText);
      setEditBody(r.body);
      setEditNew(true);
      setImp(false);
      setMsg(tr('profCompiled', { name: r.name }));
    } catch (e) {
      setMsg(`⚠ ${e instanceof Error ? e.message : String(e)}`);
    }
  };
  // One-line traffic shape from the JSON in the editor (plan P4 preview).
  const profSample = (() => {
    try {
      const p = JSON.parse(editBody) as Record<string, unknown>;
      const uris = (p.uris as string[] | undefined) ?? ['/'];
      const headers = ((p.headers ?? []) as { key: string }[]).map((h) => h.key).join(',');
      const slot = (p.data as string | undefined) ?? 'body';
      return `${p.method ?? 'POST'} ${uris[0]} · slot=${slot}${p.host ? ` · Host=${p.host}` : ''}${headers ? ` · headers=${headers}` : ''}`;
    } catch {
      return '';
    }
  })();

  return (
    <div className={asTab ? 'tabpage lsn-panel' : 'settings lsn-panel'}>
      {!asTab && <div className="crumb">{t('lsnTitle')}<span className="spacer" /><button className="back" onClick={onBack}>{tr('backSessions')}</button></div>}
      <div className="sub-tabs">
        <button className={sec === 'lsn' ? 'on' : ''} onClick={() => setSec('lsn')}>{t('lsnSecLsn')}</button>
        <button className={sec === 'fwd' ? 'on' : ''} onClick={() => setSec('fwd')}>{t('lsnSecFwd')}</button>
        <button className={sec === 'socks' ? 'on' : ''} onClick={() => setSec('socks')}>{t('lsnSecSocks')}</button>
        <button className={sec === 'prof' ? 'on' : ''} onClick={() => setSec('prof')}>{t('lsnSecProf')}</button>
        <span className="sub-note">{tf('lsnRunningN', { n: running })}</span>
      </div>
      <div className="lsn-scroll">
        {sec === 'lsn' && (
          <>
            <div className="lsn-create">
              <div className="kind-pills">
                {LSN_KINDS.map((k) => (
                  <button key={k.kind} className={kind === k.kind ? 'on' : ''} title={t(k.hint)} onClick={() => pickKind(k.kind)}>{k.label}</button>
                ))}
                <span className="lsn-tpls">
                  <button type="button" onClick={applyTpl}>{t('lsnTplHttp')}</button>
                </span>
              </div>
              <div className="lsn-fields">
                <label><span>{t('thName')}</span><input value={lname} onChange={(e) => setLname(e.target.value)} placeholder={t('namePh')} style={{ width: 130 }} /></label>
                <label><span>{t('lsnBind')}</span><input value={addr} onChange={(e) => setAddr(e.target.value)} placeholder={t('bindPh')} style={{ width: 165 }} /></label>
                <label><span>{t('lsnAdv')}</span>
                  <span className="lsn-adv-row">
                    <input value={lhost} onChange={(e) => setLhost(e.target.value)} placeholder={t('advPh')} style={{ width: 165 }} />
                    <button type="button" title={t('lsnAutoHint')} onClick={() => void detectHost()}>{t('lsnAuto')}</button>
                  </span>
                </label>
                <label><span>{t('thProfile')}</span>
                  <select value={profKind ? prof : ''} onChange={(e) => setProf(e.target.value)} disabled={!profKind}>
                    {!profKind && <option value="">—</option>}
                    {profs.map((p) => <option key={p.name} value={p.name}>{p.name}</option>)}
                  </select>
                </label>
                <button className="p" disabled={portClash} onClick={() => void create()}>{t('lsnCreate')}</button>
              </div>
              <div className="lsn-create-hint">{t(kindMeta.hint)}</div>
              {wildcard && <div className="lsn-warn">⚠ {t('lsnHostWarn')}</div>}
              {portClash && <div className="lsn-warn">⚠ {t('lsnPortUsed')} {bindPort}</div>}
              {msg && <div className="set-msg">{msg}</div>}
            </div>
            <div className="lsn-table-wrap">
              <table className="lsn-t">
                <thead><tr>
                  <th>{t('thStatus')}</th><th>{t('thName')}</th><th>{t('thKind')}</th><th>{t('thBind')}</th>
                  <th>{t('thAdv')}</th><th>{t('thProfile')}</th><th>{t('thOnline')}</th><th></th>
                </tr></thead>
                <tbody>
                  {scopedLsns.map((l) => {
                    const adv = (l.host || l.addr).trim();
                    const advWarn = !l.host && l.addr.trim().startsWith('0.0.0.0:');
                    return (
                      <tr key={l.id}>
                        <td><span className={l.running ? 'c-ok' : 'c-err'} title={l.running ? t('running') : t('stopped')}>●</span></td>
                        <td>{l.name || l.id}</td>
                        <td className="mono">{l.kind}</td>
                        <td className="mono">{l.addr}</td>
                        <td className={advWarn ? 'c-warn mono' : 'mono muted'} title={advWarn ? t('lsnHostWarn') : adv}>{l.host || '—'}{advWarn ? ' ⚠' : ''}</td>
                        <td>{l.profile || '—'}</td>
                        <td>{l.agents}</td>
                        <td className="lsn-acts">
                          <button title={t('lsnCopy')} onClick={() => copy(adv)}>⧉</button>
                          <button title={t('lsnUsePayload')} onClick={() => openInBuilder(l.id)}>📦</button>
                          {l.running
                            ? <button title={t('stopWord')} onClick={() => void act(() => Api.listeners.stop(l.id))}>■</button>
                            : <button title={t('startWord')} onClick={() => void act(() => Api.listeners.start(l.id))}>▶</button>}
                          <button title={t('lsnDetail')} onClick={() => setDetail(l)}>ⓘ</button>
                          <button title={t('lsnEdit')} onClick={() => openEdit(l)}>✎</button>
                          <button className="danger" title={t('delWord')} onClick={() => { if (confirm(`${t('cfDelLsn')} ${l.name} (${l.kind} ${l.addr})?`)) void act(() => Api.listeners.remove(l.id)); }}>✕</button>
                        </td>
                      </tr>
                    );
                  })}
                  {!scopedLsns.length && <tr><td colSpan={8} className="empty">{t('noLsn')}</td></tr>}
                </tbody>
              </table>
            </div>
            <p className="set-hint">{t('lsnHint')}</p>
          </>
        )}

        {sec === 'fwd' && (
          <section>
            <p className="set-hint">{t('fwdHint')}</p>
            <button className={`lg-chip${showHist ? ' on' : ''}`} style={{ marginBottom: 8 }} onClick={() => setShowHist((x) => !x)}>{t('pxShowHist')}</button>
            <table className="lsn-t">
              <thead><tr><th>{t('thLocal')}</th><th>{t('thTarget')}</th><th>{t('thSession')}</th><th>{t('thStatus')}</th><th></th></tr></thead>
              <tbody>
                {fwds.filter((f) => showHist || f.status === 'active').map((f) => (
                  <tr key={f.id}>
                    <td className="mono">{f.listen}</td>
                    <td className="mono">{f.target}</td>
                    <td className="mono">{f.session.slice(0, 8)}</td>
                    <td><span className={f.status === 'active' ? 'c-ok' : 'c-muted'}>{f.status === 'active' ? t('activeWord') : f.status}</span></td>
                    <td className="lsn-acts">{f.status === 'active' && <button className="danger" onClick={() => void act(() => Api.forwards.remove(f.id))}>{t('stopWord')}</button>}</td>
                  </tr>
                ))}
                {!fwds.length && <tr><td colSpan={5} className="empty">{t('noFwd')}</td></tr>}
              </tbody>
            </table>
            <div className="lsn-new">
              <select value={fSess} onChange={(e) => setFSess(e.target.value)}>
                <option value="">{t('pickSessionWord')}</option>
                {useStore.getState().sessions.filter((x) => x.status === 'online').map((x) => <option key={x.id} value={x.id}>#{x.num} {x.info.hostname}</option>)}
              </select>
              <input value={fTarget} onChange={(e) => setFTarget(e.target.value)} placeholder={t('thTarget') + ' host:port'} style={{ width: 180 }} />
              <button className="p" onClick={() => {
                if (!fSess) { setMsg(t('needSession')); return; }
                void addFwd();
              }}>{t('newFwd')}</button>
              {msg && <span className="set-msg">{msg}</span>}
            </div>
          </section>
        )}

        {sec === 'socks' && (
          <section>
            <p className="set-hint">{t('socksHint')}</p>
            <table className="lsn-t">
              <thead><tr><th>{t('thLocal')}</th><th>{t('thSession')}</th><th>{t('thStatus')}</th><th></th></tr></thead>
              <tbody>
                {sks.map((x) => (
                  <tr key={x.id}>
                    <td className="mono">{x.listen}</td>
                    <td className="mono">{x.session.slice(0, 8)}</td>
                    <td><span className={x.status === 'active' ? 'c-ok' : 'c-muted'}>{x.status === 'active' ? t('activeWord') : x.status}</span></td>
                    <td className="lsn-acts">{x.status === 'active' && <button className="danger" onClick={() => void act(() => Api.socks.remove(x.id))}>{t('stopWord')}</button>}</td>
                  </tr>
                ))}
                {!sks.length && <tr><td colSpan={4} className="empty">{t('noSocks')}</td></tr>}
              </tbody>
            </table>
            <div className="lsn-new">
              <select value={fSess} onChange={(e) => setFSess(e.target.value)}>
                <option value="">{t('pickSessionWord')}</option>
                {useStore.getState().sessions.filter((x) => x.status === 'online').map((x) => <option key={x.id} value={x.id}>#{x.num} {x.info.hostname}</option>)}
              </select>
              <button className="p" onClick={() => {
                if (!fSess) { setMsg(t('needSession')); return; }
                void addSocks();
              }}>{t('newSocks')}</button>
              {msg && <span className="set-msg">{msg}</span>}
            </div>
          </section>
        )}

        {sec === 'prof' && (
          <section>
            <div className="prof-edit">
              <div className="prof-side">
                {profs.map((p) => (
                  <div key={p.name} className={`prof-item${p.name === profName && !editNew ? ' on' : ''}`} onClick={() => { setEditNew(false); setImp(false); setProfName(p.name); }}>
                    {p.name}{p.builtin && <i>{tr("builtinWord")}</i>}
                  </div>
                ))}
                <div className="prof-item add" onClick={() => { setEditNew(true); setImp(false); setEditBody(PROFILE_TEMPLATE); }}>{t('newProf')}</div>
              </div>
              <div className="prof-main">
                <textarea value={imp ? impText : editBody} spellCheck={false}
                  placeholder={imp ? t('profImportPh') : undefined}
                  onChange={(e) => imp ? setImpText(e.target.value) : setEditBody(e.target.value)} />
                <div className="prof-btns">
                  {imp
                    ? <button className="p" onClick={() => void doImport()}>{t('profCompile')}</button>
                    : (<>
                      <button onClick={() => void lint()}>{t('validate')}</button>
                      <button className="p" onClick={() => void saveProf()}>{t('saveWord')}</button>
                    </>)}
                  <button onClick={() => setImp(!imp)}>{t(imp ? 'profBackJson' : 'profImport')}</button>
                  {!imp && !editNew && !profs.find((x) => x.name === profName)?.builtin && (
                    <button className="danger" onClick={() => { if (confirm(`${t('cfDelProf')} ${profName}?`)) void act(() => Api.profiles.remove(profName)); }}>{t('delWord')}</button>
                  )}
                  {msg && <span className="set-msg">{msg}</span>}
                </div>
                {profSample && <p className="set-hint mono">{t('profSample')}: {profSample}</p>}
              </div>
            </div>
            <p className="set-hint">{t(imp ? 'profImportHint' : 'profHint')}</p>
          </section>
        )}
      </div>
      {editLsn && (
        <div className="mdl-mask" onMouseDown={() => setEditLsn(null)}>
          <div className="mdl" onMouseDown={(e) => e.stopPropagation()}>
            <div className="mdl-hd">{t('lsnEditTitle')}<span className="mdl-x" onClick={() => setEditLsn(null)}>✕</span></div>
            <div className="mdl-body">
              <div className="mdl-note mono">{editLsn.kind} · {editLsn.addr} · {editLsn.profile || '—'}</div>
              <label>{t('thName')}</label>
              <input value={lsnName} onChange={(e) => setLsnName(e.target.value)} />
              <label>{t('lsnAdv')}</label>
              <input value={lsnHost} onChange={(e) => setLsnHost(e.target.value)} placeholder={t('advPh')} />
              <div className="mdl-note">{t('lsnEditHint')}</div>
            </div>
            <div className="mdl-ft">
              <button className="g" onClick={() => setEditLsn(null)}>{t('cancelWord')}</button>
              <button className="p" onClick={() => void saveLsn()}>{t('saveWord')}</button>
            </div>
          </div>
        </div>
      )}
      {detail && (() => {
        const dl = lsns.find((x) => x.id === detail.id) ?? detail;
        const adv = (dl.host || dl.addr).trim();
        const p = profs.find((x) => x.name === dl.profile);
        let preview = '';
        if (p) {
          try { preview = JSON.stringify(JSON.parse(p.body), null, 2); } catch { preview = p.body; }
        }
        const online = sessions.filter((s) => s.listener === dl.id && s.status === 'online');
        const fmtDay = (iso: string) => {
          const d = new Date(iso);
          return Number.isNaN(+d) ? '—' : d.toLocaleDateString();
        };
        const transport =
          dl.kind === 'https' ? `HTTPS · ${t('lsnTlsSelf')}` :
          dl.kind === 'http' ? `HTTP · ${t('lsnNoTls')}` :
          dl.kind === 'tcp' ? `TCP · ${t('lsnRaw')}` :
          dl.kind === 'kcp' ? `KCP/UDP · ${t('lsnRaw')}` :
          dl.kind === 'quic' ? `QUIC/UDP · ${t('lsnKindQuic')}` :
          dl.kind === 'rcp-kcp' ? `RCP-KCP · ${t('lsnRcpTransport')}` :
          `RCP · ${t('lsnRcpTransport')}`;
        return (
          <div className="mdl-mask" onMouseDown={() => setDetail(null)}>
            <div className="mdl lsn-detail" onMouseDown={(e) => e.stopPropagation()}>
              <div className="mdl-hd">
                <span className={dl.running ? 'c-ok' : 'c-err'}>●</span>
                <span style={{ marginLeft: 6 }}>{dl.name || dl.id}</span>
                <span className="lsn-detail-kind mono">{dl.kind}</span>
                <span className="mdl-x" onClick={() => setDetail(null)}>✕</span>
              </div>
              <div className="mdl-body">
                <div className="lsn-meta">
                  <div><label>{t('lsnBind')}</label><span className="mono">{dl.addr}</span></div>
                  <div><label>{t('lsnAdv')}</label><span className="mono">{adv}</span></div>
                  <div><label>{t('thProfile')}</label><span>{dl.profile || '—'}</span></div>
                  <div><label>{t('thOnline')}</label><span>{online.length} / {dl.agents}</span></div>
                </div>
                <div className="lsn-detail-sec">
                  <h4>{t('lsnTransport')}</h4>
                  <div className="mono lsn-detail-line">{transport}</div>
                </div>
                <div className="lsn-detail-sec">
                  <h4>{t('lsnStats')}</h4>
                  {(() => {
                    const st = dl.stats;
                    const active = !!st && ((st.requests ?? 0) > 0 || st.bytes_in > 0 || st.bytes_out > 0);
                    if (!st || !active) return <div className="mdl-note">{t('lsnStatsNone')}</div>;
                    return (<>
                      <div className="lsn-meta">
                        {(st.requests ?? 0) > 0 && <div><label>{t('lsnStatsReq')}</label><span>{st.requests}</span></div>}
                        <div><label>{t('lsnStatsErr')}</label><span className={st.errors ? 'c-warn' : ''}>{st.errors}</span></div>
                        <div><label>{t('lsnStatsIn')}</label><span>{fmtSize(st.bytes_in)}</span></div>
                        <div><label>{t('lsnStatsOut')}</label><span>{fmtSize(st.bytes_out)}</span></div>
                        <div><label>{t('lsnStatsSeen')}</label><span>{st.last_seen ? new Date(st.last_seen).toLocaleString() : '—'}</span></div>
                      </div>
                      {st.last_error && <div className="mdl-note mono lsn-last-err" title={st.last_error}>{t('lsnLastErr')}: {st.last_error}</div>}
                    </>);
                  })()}
                </div>
                {dl.kind === 'https' && (() => {
                  const tls = dl.tls;
                  const days = tls ? Math.ceil((Date.parse(tls.not_after) - Date.now()) / 86400000) : 0;
                  const sans = tls ? [...(tls.dns ?? []), ...(tls.ips ?? [])] : [];
                  return (
                    <div className="lsn-detail-sec">
                      <h4>
                        {t('lsnTlsCert')}
                        {tls?.imported && <span className="lsn-cert-badge">{t('lsnCertImported')}</span>}
                      </h4>
                      {!tls && <div className="mdl-note">{t('lsnTlsNoCert')}</div>}
                      {tls && (<>
                        <div className="lsn-meta">
                          <div><label>{t('lsnTlsSubject')}</label><span className="mono" title={tls.subject}>{tls.subject}</span></div>
                          <div><label>{t('lsnTlsIssuer')}</label><span className="mono">{tls.self_signed ? t('lsnTlsSelfSigned') : tls.issuer}</span></div>
                          <div><label>{t('lsnTlsValid')}</label><span className="mono">{fmtDay(tls.not_before)} → {fmtDay(tls.not_after)}</span></div>
                          <div><label>{t('lsnTlsExpires')}</label><span className={days <= 7 ? 'c-warn' : ''}>{days > 0 ? tf('lsnTlsDays', { n: days }) : t('lsnTlsExpired')}</span></div>
                        </div>
                        <div className="lsn-tls-fp">
                          <span className="mono" title={tls.sha256}>{tls.sha256}</span>
                          <button className="pl-mini" title={t('lsnCopy')} onClick={() => {
                            void navigator.clipboard.writeText(tls.sha256)
                              .then(() => useStore.getState().toast({ kind: 'ok', text: t('lsnCopied') }))
                              .catch(() => {});
                          }}>⧉</button>
                        </div>
                        {sans.length > 0 && <div className="mdl-note mono">{t('lsnTlsSan')}: {sans.join(', ')}</div>}
                      </>)}
                      <div className="lsn-cert-acts">
                        <button className="g" onClick={() => { setCertOpen(true); setCertMsg(''); }}>⬆ {t('lsnCertImport')}</button>
                        {tls?.imported && <button className="g" onClick={() => void clearCert()}>↺ {t('lsnCertClear')}</button>}
                      </div>
                    </div>
                  );
                })()}
                <div className="lsn-detail-sec">
                  <h4>{t('lsnOnlineAgents')}</h4>
                  {online.map((s) => (
                    <button
                      key={s.id}
                      className="lsn-agent-row"
                      onClick={() => {
                        useStore.getState().setSelected(s.id);
                        useStore.getState().openTab('term', s.id);
                        setDetail(null);
                      }}
                    >
                      <span className="mono">#{s.num}</span>
                      <span>{s.info.hostname}</span>
                      <span className="muted">{s.info.user}@{s.info.internal_ip || '—'}</span>
                      <span className="lsn-agent-go">{t('lsnJumpShell')} ›</span>
                    </button>
                  ))}
                  {!online.length && <div className="mdl-note">{t('lsnNoAgents')}</div>}
                </div>
                {p && (
                  <div className="lsn-detail-sec">
                    <h4>{t('lsnProfilePreview')} · <span className="lsn-prof-name">{p.name}</span></h4>
                    <pre className="lsn-prof-preview">{preview}</pre>
                  </div>
                )}
              </div>
              <div className="mdl-ft">
                <button className="g" onClick={() => {
                  void navigator.clipboard.writeText(adv)
                    .then(() => useStore.getState().toast({ kind: 'ok', text: `${t('lsnCopied')} ${adv}` }))
                    .catch(() => {});
                }}>⧉ {t('lsnCopy')}</button>
                <button className="g" onClick={() => { setDetail(null); openInBuilder(dl.id); }}>📦 {t('lsnUsePayload')}</button>
                <button className="g" onClick={() => { setDetail(null); openEdit(dl); }}>✎ {t('lsnEdit')}</button>
                <button className="p" onClick={() => setDetail(null)}>{t('closeWord')}</button>
              </div>
            </div>
          </div>
        );
      })()}
      {certOpen && detail && (
        <div className="mdl-mask" onMouseDown={() => { if (!certBusy) setCertOpen(false); }}>
          <div className="mdl lsn-cert-mdl" onMouseDown={(e) => e.stopPropagation()}>
            <div className="mdl-hd">
              {t('lsnCertImportT')}
              <span className="mdl-x" onClick={() => { if (!certBusy) setCertOpen(false); }}>✕</span>
            </div>
            <div className="mdl-body">
              <div className="mdl-note mono">{detail.name || detail.id} · {detail.addr}</div>
              <label>{t('lsnCertPem')}</label>
              <input type="file" className="cert-file" accept=".pem,.crt,.cer"
                onChange={readPem(setCertPem)} />
              <textarea className="cert-ta" spellCheck={false} value={certPem}
                placeholder="-----BEGIN CERTIFICATE-----"
                onChange={(e) => setCertPem(e.target.value)} />
              <label>{t('lsnCertKey')}</label>
              <input type="file" className="cert-file" accept=".pem,.key"
                onChange={readPem(setKeyPem)} />
              <textarea className="cert-ta" spellCheck={false} value={keyPem}
                placeholder="-----BEGIN PRIVATE KEY-----"
                onChange={(e) => setKeyPem(e.target.value)} />
              <div className="mdl-note">{t('lsnCertHint')}</div>
              {certMsg && <div className="mdl-err">{certMsg}</div>}
            </div>
            <div className="mdl-ft">
              <button className="g" disabled={certBusy} onClick={() => setCertOpen(false)}>{t('cancelWord')}</button>
              <button className="p" disabled={certBusy || !certPem.trim() || !keyPem.trim()} onClick={() => void saveCert()}>{t('saveWord')}</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

