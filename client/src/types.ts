export interface SystemInfo {
  hostname: string;
  os: string;
  arch: string;
  user: string;
  pid: number;
  process: string;
  agent_ver: string;
  internal_ip?: string;
}

export interface Session {
  num: number;
  id: string;
  project: string;
  listener: string;
  status: 'online' | 'idle' | 'offline';
  last_seen: string;
  first_seen: string;
  seq: number;
  pending: number;
  info: SystemInfo;
  caps?: string[];
  tags?: string[];
  notes?: string;
  color?: string;
}

export interface TaskPayload {
  id: string;
  cmd: number;
  created: number;
  args?: unknown;
}

export interface TaskRecord {
  task: TaskPayload;
  session: string;
  project: string;
  status: 'pending' | 'sent' | 'completed' | 'failed';
  updated: number;
  result?: { task_id: string; ok: boolean; exit: number; output: string };
}

export interface TeamEvent {
  time: string;
  level: 'info' | 'ok' | 'warn' | 'err';
  kind: string;
  project?: string;
  text: string;
}

export interface Project {
  ID: string;
  Name: string;
  Color: string;
}

export interface LsEntry { name: string; dir: boolean; size: number; mtime: number }

export interface SysDetail {
  hostname?: string; os?: string; arch?: string; user?: string;
  pid?: number; process?: string; agent_ver?: string; internal_ip?: string;
}

export interface FileJob {
  id: string; agent: string; project: string;
  mode: 'up' | 'down'; remote: string; local: string;
  size: number; chunk: number; received: number; sha256: string; status: string; created: number;
}

export interface Metrics {
  uptime_sec: number; goroutines: number; heap_alloc: number;
  sessions_total: number; sessions_online: number; sessions_idle: number; sessions_offline: number;
  tasks_pending: number; tasks_sent: number; tasks_completed: number; tasks_failed: number;
  jobs_active: number; jobs_done: number; jobs_failed: number;
  listeners_total: number; listeners_running: number; rcp_online: number; stage_active: number;
}

export interface PayloadMeta {
  id: string; name: string; os: string; arch: string; mode: string;
  agent: string; format: string; delivery: string; loader: string;
  source: string; profile?: string; poly?: boolean;
  hint?: string;
  sha256: string; size: number; created: string;
  note?: string; listener?: string; project?: string;
  stage_until?: string; stage_left?: number; stage_total?: number; stage_active?: boolean;
}

export interface PayloadCombo {
  agent: string; os: string; arch: string;
  format: string; delivery: string; loader: string;
}

export interface PayloadPlannedOption {
  kind: 'format' | 'delivery' | 'loader' | 'feature';
  id: string; phase: string;
}

export interface PayloadCapabilities {
  schema: number;
  combos: PayloadCombo[];
  known: {
    agents: string[]; formats: string[]; deliveries: string[]; loaders: string[];
  };
  planned: PayloadPlannedOption[];
  features: Record<string, boolean>;
}

export interface TemplateFileInfo {
  name: string; sha256?: string; size: number; match: boolean; error?: string;
}

export interface TemplateSetInfo {
  kind: string; present: boolean; ok: boolean;
  schema?: number; agent?: string; toolchain?: string; features?: string[]; source?: string;
  git?: string; dirty?: boolean; built_at?: string;
  files: TemplateFileInfo[]; error?: string;
}

export interface TemplatesInfo {
  platforms: string[]; rs_available: boolean;
  stage_path?: string; stage_ttl_seconds?: number; stage_uses?: number;
  go: TemplateSetInfo; rs: TemplateSetInfo; c: TemplateSetInfo; cpp: TemplateSetInfo; srdi: TemplateSetInfo;
}

export interface FServerStatus {
  running: boolean; url: string; host: string; root_dir: string; addr: string; port: number;
  use_tls: boolean; mode: string; tls: boolean; deliveries: number; shares: number; error?: string;
}

export interface FServerConfig {
  root_dir: string; port?: number; addr?: string; host: string; use_tls: boolean;
  enabled: boolean; mode: string; cert_file?: string; key_file?: string; no_landing?: boolean;
}

export interface DeliveryRow {
  id: string; token: string; payload: string; name: string; project: string;
  content_type?: string; expires_at?: number; max_downloads?: number;
  downloads: number; requests: number; bytes_out: number; revoked: boolean;
  created: number; last_seen?: number; url: string;
}

export interface ShareRow {
  id: string; token: string; name: string; file: string; project: string;
  has_password: boolean; expires_at?: number; max_downloads?: number;
  downloads: number; requests: number; bytes_out: number; revoked: boolean;
  created: number; last_seen?: number; url: string;
}

export interface RootFileRow { name: string; path: string; size: number; mod_time: string }

export interface ListenerTLS {
  subject: string; issuer: string; self_signed: boolean; imported: boolean;
  not_before: string; not_after: string; sha256: string;
  dns?: string[]; ips?: string[];
}

export interface ListenerStats {
  requests?: number; bytes_in: number; bytes_out: number; errors: number;
  last_error?: string; last_seen?: string;
}

export interface ListenerRow {
  id: string; name: string; kind: string; addr: string; host: string;
  profile: string; project: string; running: boolean; agents: number;
  tls?: ListenerTLS; stats?: ListenerStats;
}

export interface ListenerSpec {
  name?: string; kind: string; addr: string; host?: string; profile?: string; project?: string;
}

export interface ProfileRow {
  name: string; body: string; builtin?: boolean;
}

export interface ForwardRow {
  id: string; session: string; listen: string; target: string; status: string;
}

export interface SocksRow {
  id: string; session: string; listen: string; status: string;
}

export interface PayloadSpec {
  os: string; arch: string; staged?: boolean; rs_staged?: boolean;
  agent?: string; format?: string; delivery?: string; loader?: string;
  profile?: string; source?: string;
  poly?: { enabled?: boolean; passes?: number; seed?: string };
  listener?: string; project?: string; sleep_ms?: number; jitter_pct?: number; note?: string;
  stage_ttl_seconds?: number; stage_uses?: number;
}
