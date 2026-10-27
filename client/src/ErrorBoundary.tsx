import { Component, type ErrorInfo, type ReactNode } from 'react';
import { useI18n } from './i18n';

export class ErrorBoundary extends Component<{ children: ReactNode }, { err?: Error }> {
  state: { err?: Error } = {};
  static getDerivedStateFromError(err: Error) {
    return { err };
  }
  componentDidCatch(err: Error, info: ErrorInfo) {
    console.error('UI crash:', err, info.componentStack);
  }
  render() {
    if (this.state.err) {
      return (
        <div className="gate">
          <div className="gate-card">
            <h1>{useI18n.getState().t('errRender')}</h1>
            <p>{String(this.state.err.message ?? this.state.err)}</p>
            <button onClick={() => location.reload()}>{useI18n.getState().t('reloadWord')}</button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}
