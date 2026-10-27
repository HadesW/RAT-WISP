import type { DeliveryRow, FileJob, ForwardRow, FServerConfig, FServerStatus, ListenerRow, ListenerSpec, Metrics, PayloadCapabilities, PayloadMeta, PayloadSpec, ProfileRow, Project, RootFileRow, ShareRow, SocksRow, TemplatesInfo } from './types';

// Typed API client: one place for the auth header, JSON encoding and errors.
// Keep new features on this path instead of scattering fetch() calls.

export class ApiError extends Error {
  status: number;
  data: unknown;
  constructor(message: string, status: number, data: unknown) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.data = data;
  }
}

export interface ApiInit {
  method?: string;
  body?: unknown;
  raw?: BodyInit;
  signal?: AbortSignal;
}

const token = () => localStorage.getItem('wisp_token') ?? '';

export async function api<T>(path: string, init: ApiInit = {}): Promise<T> {
  const headers: Record<string, string> = { 'X-Wisp-Token': token() };
  let body: BodyInit | undefined;
  if (init.raw !== undefined) {
    body = init.raw;
  } else if (init.body !== undefined) {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(init.body);
  }
  let res: Response;
  try {
    res = await fetch(path, { method: init.method ?? 'GET', headers, body, signal: init.signal });
  } catch (e) {
    throw new ApiError(e instanceof Error ? e.message : String(e), 0, null);
  }
  if (res.status === 204) return undefined as T;
  const text = await res.text();
  let data: unknown = null;
  if (text) {
    try { data = JSON.parse(text); } catch { data = text; }
  }
  if (!res.ok) {
    const msg = data && typeof data === 'object' && 'error' in data
      ? String((data as { error: unknown }).error)
      : `HTTP ${res.status}`;
    throw new ApiError(msg, res.status, data);
  }
  return data as T;
}

const get = <T>(path: string) => api<T>(path);
const post = <T>(path: string, body?: unknown) => api<T>(path, { method: 'POST', body });
const put = <T>(path: string, body?: unknown) => api<T>(path, { method: 'PUT', body });
const patch = <T>(path: string, body?: unknown) => api<T>(path, { method: 'PATCH', body });
const del = <T>(path: string) => api<T>(path, { method: 'DELETE' });

export const Api = {
  listeners: {
    list: () => get<ListenerRow[]>('/api/listeners'),
    create: (spec: ListenerSpec) => post<ListenerRow>('/api/listeners', spec),
    update: (id: string, patchBody: { name?: string; host?: string }) => patch<void>(`/api/listeners/${id}`, patchBody),
    start: (id: string) => post<void>(`/api/listeners/${id}/start`),
    stop: (id: string) => post<void>(`/api/listeners/${id}/stop`),
    setCert: (id: string, certPem: string, keyPem: string) =>
      post<void>(`/api/listeners/${id}/cert`, { cert_pem: certPem, key_pem: keyPem }),
    clearCert: (id: string) => del<void>(`/api/listeners/${id}/cert`),
    remove: (id: string) => del<void>(`/api/listeners/${id}`),
  },
  net: {
    ips: () => get<{ ips: string[] }>('/api/net/ips'),
  },
  projects: {
    list: () => get<Project[]>('/api/projects'),
    create: (id: string, name: string, color: string) => post<Project>('/api/projects', { id, name, color }),
    update: (id: string, patchBody: { name?: string; color?: string }) =>
      patch<Project>(`/api/projects/${encodeURIComponent(id)}`, patchBody),
  },
  metrics: () => get<Metrics>('/api/metrics'),
  profiles: {
    list: () => get<ProfileRow[]>('/api/profiles'),
    save: (name: string, body: string) => put<void>('/api/profiles', { name, body }),
    remove: (name: string) => del<void>(`/api/profiles/${encodeURIComponent(name)}`),
    validate: (body: string) => post<{ ok: boolean; error?: string }>('/api/profiles/validate', { body }),
    importProfile: (name: string, text: string) =>
      post<{ ok: boolean; name: string; body: string }>('/api/profiles/import', { name, text }),
  },
  forwards: {
    list: () => get<ForwardRow[]>('/api/forwards'),
    create: (session: string, target: string) =>
      post<{ id?: string; listen: string; target: string }>('/api/forwards', { session, listen: '127.0.0.1:0', target }),
    remove: (id: string) => del<void>(`/api/forwards/${id}`),
  },
  socks: {
    list: () => get<SocksRow[]>('/api/socks'),
    create: (session: string) => post<{ id?: string; listen: string }>('/api/socks', { session, listen: '127.0.0.1:0' }),
    remove: (id: string) => del<void>(`/api/socks/${id}`),
  },
  payloads: {
    platforms: () => get<string[]>('/api/payloads/platforms'),
    capabilities: () => get<PayloadCapabilities>('/api/payloads/capabilities'),
    list: (project = '') => get<PayloadMeta[]>(`/api/payloads${project ? `?project=${encodeURIComponent(project)}` : ''}`),
    templates: () => get<TemplatesInfo>('/api/payloads/templates'),
    create: (spec: PayloadSpec) => post<PayloadMeta>('/api/payloads', spec),
    remove: (id: string) => del<void>(`/api/payloads/${id}`),
    rearm: (id: string, body: { stage_ttl_seconds: number; stage_uses: number }) =>
      post<PayloadMeta>(`/api/payloads/${id}/rearm`, body),
    push: (id: string, body: { session: string; remote: string }) =>
      post<{ job?: FileJob; remote: string }>(`/api/payloads/${id}/push`, body),
  },
  fserver: {
    status: () => get<FServerStatus>('/api/fileserver'),
    apply: (cfg: FServerConfig) => put<FServerStatus>('/api/fileserver', cfg),
    setCert: (certPem: string, keyPem: string) =>
      post<FServerStatus>('/api/fileserver/cert', { cert_pem: certPem, key_pem: keyPem }),
  },
  deliveries: {
    list: (project = '') => get<DeliveryRow[]>(`/api/deliveries${project ? `?project=${encodeURIComponent(project)}` : ''}`),
    create: (body: { payload_id: string; name?: string; ttl_seconds?: number; max_downloads?: number; content_type?: string }) =>
      post<DeliveryRow>('/api/deliveries', body),
    patch: (id: string, body: { expires_in_seconds?: number; max_downloads?: number; content_type?: string; revoked?: boolean }) =>
      patch<void>(`/api/deliveries/${id}`, body),
    remove: (id: string) => del<void>(`/api/deliveries/${id}`),
  },
  shares: {
    list: (project = '') => get<ShareRow[]>(`/api/shares${project ? `?project=${encodeURIComponent(project)}` : ''}`),
    files: () => get<RootFileRow[]>('/api/shares/files'),
    create: (body: { file: string; name?: string; ttl_seconds?: number; max_downloads?: number; password?: string }) =>
      post<ShareRow>('/api/shares', body),
    patch: (id: string, body: { expires_in_seconds?: number; max_downloads?: number; password?: string; revoked?: boolean }) =>
      patch<void>(`/api/shares/${id}`, body),
    remove: (id: string) => del<void>(`/api/shares/${id}`),
  },
  files: {
    jobs: (project = '') => get<FileJob[]>(`/api/files${project ? `?project=${encodeURIComponent(project)}` : ''}`),
    grab: (session: string, remote: string) => post<FileJob>(`/api/sessions/${session}/files`, { mode: 'up', remote }),
    push: (session: string, remote: string, inbox: string) =>
      post<FileJob>(`/api/sessions/${session}/files`, { mode: 'down', remote, inbox }),
    upload: (name: string, file: Blob) =>
      api<{ inbox: string; name?: string }>(`/api/files/upload?name=${encodeURIComponent(name)}`, { method: 'POST', raw: file }),
    retry: (id: string) => post<void>(`/api/files/${id}/retry`),
    downloadUrl: (id: string) => `/api/files/${id}/download?token=${encodeURIComponent(token())}`,
  },
  rcp: {
    status: (session: string) => get<{ online: boolean }>(`/api/rcp/${session}/status`),
    connect: (session: string) => post<unknown>(`/api/rcp/${session}/connect`),
  },
  sessions: {
    task: (session: string, cmd: string, args: unknown) =>
      post<{ task?: { id?: string } }>(`/api/sessions/${session}/tasks`, { cmd, args }),
    remove: (session: string) => del<void>(`/api/sessions/${session}`),
  },
};
