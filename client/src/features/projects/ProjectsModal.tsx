import { useEffect, useState } from 'react';
import { useI18n } from '../../i18n';
import { useStore } from '../../store';
import { Api } from '../../api';

export default function ProjectsModal({ onClose }: { onClose: () => void }) {
  const { t } = useI18n();
  const projects = useStore((s) => s.projects);
  const [id, setId] = useState('');
  const [name, setName] = useState('');
  const [color, setColor] = useState('#8B93A7');
  const [edit, setEdit] = useState<Record<string, { name: string; color: string }>>({});
  const [msg, setMsg] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    setEdit((prev) => {
      const next = { ...prev };
      for (const p of projects) {
        if (!next[p.ID]) next[p.ID] = { name: p.Name, color: p.Color };
      }
      return next;
    });
  }, [projects]);

  const create = async () => {
    setBusy(true); setMsg('');
    try {
      const p = await Api.projects.create(id.trim(), name.trim(), color);
      setId(''); setName('');
      await useStore.getState().refresh();
      useStore.getState().setProject(p.ID);
      setMsg(`✓ ${t('projCreateOk')} ${p.ID}`);
    } catch (e) {
      setMsg(`⚠ ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setBusy(false);
    }
  };

  const save = async (pid: string) => {
    const v = edit[pid];
    if (!v) return;
    setBusy(true); setMsg('');
    try {
      await Api.projects.update(pid, { name: v.name, color: v.color });
      await useStore.getState().refresh();
      setMsg(`✓ ${t('projSaved')} ${pid}`);
    } catch (e) {
      setMsg(`⚠ ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="mdl-mask" onMouseDown={onClose}>
      <div className="mdl proj-mdl" onMouseDown={(e) => e.stopPropagation()}>
        <div className="mdl-hd">{t('projManage')}<span className="mdl-x" onClick={onClose}>✕</span></div>
        <div className="mdl-body">
          <label>{t('projCreate')}</label>
          <div className="proj-new">
            <input placeholder={t('projId')} value={id} onChange={(e) => setId(e.target.value)} />
            <input placeholder={t('projName')} value={name} onChange={(e) => setName(e.target.value)} />
            <input type="color" value={color} onChange={(e) => setColor(e.target.value)} title={t('projColor')} />
            <button className="p" disabled={busy || !id.trim()} onClick={() => void create()}>{t('projCreateGo')}</button>
          </div>
          <div className="mdl-note">{t('projIdHint')}</div>
          <div className="proj-list">
            {projects.map((p) => (
              <div className="proj-row" key={p.ID}>
                <span className="mono" title={p.ID}>{p.ID}</span>
                <input
                  value={edit[p.ID]?.name ?? p.Name}
                  onChange={(e) => setEdit({ ...edit, [p.ID]: { name: e.target.value, color: edit[p.ID]?.color ?? p.Color } })}
                />
                <input
                  type="color"
                  value={edit[p.ID]?.color ?? p.Color}
                  title={t('projColor')}
                  onChange={(e) => setEdit({ ...edit, [p.ID]: { name: edit[p.ID]?.name ?? p.Name, color: e.target.value } })}
                />
                <button className="g" disabled={busy} onClick={() => void save(p.ID)}>{t('saveWord')}</button>
              </div>
            ))}
            {!projects.length && <div className="empty">{t('mtrEmpty')}</div>}
          </div>
          {msg && <div className={msg.startsWith('⚠') ? 'mdl-err' : 'mdl-ok'}>{msg}</div>}
        </div>
        <div className="mdl-ft">
          <button className="g" onClick={onClose}>{t('closeWord')}</button>
        </div>
      </div>
    </div>
  );
}