import { useT } from '../i18n'

interface ConfirmDialogProps {
  title: string
  message?: string
  onCancel: () => void
  onOk: () => void
}

// ConfirmDialog is a lightweight in-app confirmation modal. Wails webviews do
// not implement window.confirm, so confirmations must be rendered in React.
export function ConfirmDialog({ title, message, onCancel, onOk }: ConfirmDialogProps) {
  const t = useT()
  return (
    <div className="dialog-overlay" onClick={onCancel}>
      <div className="dialog" onClick={e => e.stopPropagation()}>
        <h2>{title}</h2>
        {message && <p style={{ marginBottom: 12, color: 'var(--text-muted)', fontSize: 13 }}>{message}</p>}
        <div className="dialog-actions">
          <button onClick={onCancel}>{t('fsCancel')}</button>
          <button className="btn-primary" onClick={onOk}>{t('dlgOk')}</button>
        </div>
      </div>
    </div>
  )
}
