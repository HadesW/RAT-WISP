#pragma once

#include <windows.h>

// Type2 RCP client (shared/protocol/rcp.go): agent-initiated, multiplexed
// channel carrying shell/view/fwd/file. Started on CmdRCPConnect(23) and
// stopped on CmdRCPDisconnect(24) or process exit.
BOOL WispRcpStart(const char* addr, const char* token, const char* agentId);
void WispRcpStop(void);
BOOL WispRcpRunning(void);
