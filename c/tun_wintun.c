/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.
 */
#ifdef _WIN32
#include <winsock2.h>
#include <Windows.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <mstcpip.h>
#include <ip2string.h>
#include <winternl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include "wintun.h"

#pragma comment(lib, "Ntdll.lib")

static WINTUN_CREATE_ADAPTER_FUNC* WintunCreateAdapter;
static WINTUN_CLOSE_ADAPTER_FUNC* WintunCloseAdapter;
static WINTUN_OPEN_ADAPTER_FUNC* WintunOpenAdapter;
static WINTUN_GET_ADAPTER_LUID_FUNC* WintunGetAdapterLUID;
static WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC* WintunGetRunningDriverVersion;
static WINTUN_DELETE_DRIVER_FUNC* WintunDeleteDriver;
static WINTUN_SET_LOGGER_FUNC* WintunSetLogger;
static WINTUN_START_SESSION_FUNC* WintunStartSession;
static WINTUN_END_SESSION_FUNC* WintunEndSession;
static WINTUN_GET_READ_WAIT_EVENT_FUNC* WintunGetReadWaitEvent;
static WINTUN_RECEIVE_PACKET_FUNC* WintunReceivePacket;
static WINTUN_RELEASE_RECEIVE_PACKET_FUNC* WintunReleaseReceivePacket;
static WINTUN_ALLOCATE_SEND_PACKET_FUNC* WintunAllocateSendPacket;
static WINTUN_SEND_PACKET_FUNC* WintunSendPacket;

static HMODULE
InitializeWintun(void)
{
        HMODULE Wintun =
                LoadLibraryExW(L"wintun.dll", NULL, LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!Wintun)
                return NULL;
#define X(Name) ((*(FARPROC *)&Name = GetProcAddress(Wintun, #Name)) == NULL)
        if (X(WintunCreateAdapter) || X(WintunCloseAdapter) || X(WintunOpenAdapter) || X(WintunGetAdapterLUID) ||
                X(WintunGetRunningDriverVersion) || X(WintunDeleteDriver) || X(WintunSetLogger) || X(WintunStartSession) ||
                X(WintunEndSession) || X(WintunGetReadWaitEvent) || X(WintunReceivePacket) || X(WintunReleaseReceivePacket) ||
                X(WintunAllocateSendPacket) || X(WintunSendPacket))
#undef X
        {
                DWORD LastError = GetLastError();
                FreeLibrary(Wintun);
                SetLastError(LastError);
                return NULL;
        }
        return Wintun;
}

static void CALLBACK
ConsoleLogger(_In_ WINTUN_LOGGER_LEVEL Level, _In_ DWORD64 Timestamp, _In_z_ const WCHAR* LogLine)
{
        SYSTEMTIME SystemTime;
        FileTimeToSystemTime((FILETIME*)&Timestamp, &SystemTime);
        WCHAR LevelMarker;
        switch (Level)
        {
        case WINTUN_LOG_INFO:
                LevelMarker = L'+';
                break;
        case WINTUN_LOG_WARN:
                LevelMarker = L'-';
                break;
        case WINTUN_LOG_ERR:
                LevelMarker = L'!';
                break;
        default:
                return;
        }
        fwprintf(
                stderr,
                L"%04u-%02u-%02u %02u:%02u:%02u.%04u [%c] %s\n",
                SystemTime.wYear,
                SystemTime.wMonth,
                SystemTime.wDay,
                SystemTime.wHour,
                SystemTime.wMinute,
                SystemTime.wSecond,
                SystemTime.wMilliseconds,
                LevelMarker,
                LogLine);
}

static DWORD64 Now(VOID)
{
#if 0
        LARGE_INTEGER Timestamp;
        NtQuerySystemTime(&Timestamp);
        return Timestamp.QuadPart;
#else
        FILETIME Timestamp;
        GetSystemTimeAsFileTime(&Timestamp);
        return *((DWORD64*)(&Timestamp));
#endif
}

static DWORD
LogError(_In_z_ const WCHAR* Prefix, _In_ DWORD Error)
{
        WCHAR* SystemMessage = NULL, * FormattedMessage = NULL;
        FormatMessageW(
                FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_MAX_WIDTH_MASK,
                NULL,
                HRESULT_FROM_SETUPAPI(Error),
                MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                (void*)&SystemMessage,
                0,
                NULL);
        FormatMessageW(
                FORMAT_MESSAGE_FROM_STRING | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_ARGUMENT_ARRAY |
                FORMAT_MESSAGE_MAX_WIDTH_MASK,
                SystemMessage ? L"%1: %3(Code 0x%2!08X!)" : L"%1: Code 0x%2!08X!",
                0,
                0,
                (void*)&FormattedMessage,
                0,
                (va_list*)(DWORD_PTR[]) { (DWORD_PTR)Prefix, (DWORD_PTR)Error, (DWORD_PTR)SystemMessage });
        if (FormattedMessage)
                ConsoleLogger(WINTUN_LOG_ERR, Now(), FormattedMessage);
        LocalFree(FormattedMessage);
        LocalFree(SystemMessage);
        return Error;
}

static DWORD
LogLastError(_In_z_ const WCHAR* Prefix)
{
        DWORD LastError = GetLastError();
        LogError(Prefix, LastError);
        SetLastError(LastError);
        return LastError;
}

static void
Log(_In_ WINTUN_LOGGER_LEVEL Level, _In_z_ const WCHAR* Format, ...)
{
        WCHAR LogLine[0x200];
        va_list args;
        va_start(args, Format);
        _vsnwprintf_s(LogLine, _countof(LogLine), _TRUNCATE, Format, args);
        va_end(args);
        ConsoleLogger(Level, Now(), LogLine);
}

static HANDLE QuitEvent;
static volatile BOOL HaveQuit;

static BOOL WINAPI
CtrlHandler(_In_ DWORD CtrlType)
{
        switch (CtrlType)
        {
        case CTRL_C_EVENT:
        case CTRL_BREAK_EVENT:
        case CTRL_CLOSE_EVENT:
        case CTRL_LOGOFF_EVENT:
        case CTRL_SHUTDOWN_EVENT:
                Log(WINTUN_LOG_INFO, L"Cleaning up and shutting down...");
                HaveQuit = TRUE;
                SetEvent(QuitEvent);
                return TRUE;
        }
        return FALSE;
}

static void
PrintPacket(_In_ const BYTE* Packet, _In_ DWORD PacketSize)
{
        if (PacketSize < 20)
        {
                Log(WINTUN_LOG_INFO, L"Received packet without room for an IP header");
                return;
        }
        BYTE IpVersion = Packet[0] >> 4, Proto;
        WCHAR Src[46], Dst[46];
        if (IpVersion == 4)
        {
                RtlIpv4AddressToStringW((struct in_addr*)&Packet[12], Src);
                RtlIpv4AddressToStringW((struct in_addr*)&Packet[16], Dst);
                Proto = Packet[9];
                Packet += 20, PacketSize -= 20;
        }
        else if (IpVersion == 6 && PacketSize < 40)
        {
                Log(WINTUN_LOG_INFO, L"Received packet without room for an IP header");
                return;
        }
        else if (IpVersion == 6)
        {
                RtlIpv6AddressToStringW((struct in6_addr*)&Packet[8], Src);
                RtlIpv6AddressToStringW((struct in6_addr*)&Packet[24], Dst);
                Proto = Packet[6];
                Packet += 40, PacketSize -= 40;
        }
        else
        {
                Log(WINTUN_LOG_INFO, L"Received packet that was not IP");
                return;
        }
        if (Proto == 1 && PacketSize >= 8 && Packet[0] == 0)
                Log(WINTUN_LOG_INFO, L"Received IPv%d ICMP echo reply from %s to %s", IpVersion, Src, Dst);
        else
                Log(WINTUN_LOG_INFO, L"Received IPv%d proto 0x%x packet from %s to %s", IpVersion, Proto, Src, Dst);
}

static USHORT
IPChecksum(_In_reads_bytes_(Len) BYTE* Buffer, _In_ DWORD Len)
{
        ULONG Sum = 0;
        for (; Len > 1; Len -= 2, Buffer += 2)
                Sum += *(USHORT*)Buffer;
        if (Len)
                Sum += *Buffer;
        Sum = (Sum >> 16) + (Sum & 0xffff);
        Sum += (Sum >> 16);
        return (USHORT)(~Sum);
}

static void
MakeICMP(_Out_writes_bytes_all_(28) BYTE Packet[28])
{
        memset(Packet, 0, 28);
        Packet[0] = 0x45;
        *(USHORT*)&Packet[2] = htons(28);
        Packet[8] = 255;
        Packet[9] = 1;
        *(ULONG*)&Packet[12] = htonl((10 << 24) | (6 << 16) | (7 << 8) | (8 << 0)); /* 10.6.7.8 */
        *(ULONG*)&Packet[16] = htonl((10 << 24) | (6 << 16) | (7 << 8) | (7 << 0)); /* 10.6.7.7 */
        *(USHORT*)&Packet[10] = IPChecksum(Packet, 20);
        Packet[20] = 8;
        *(USHORT*)&Packet[22] = IPChecksum(&Packet[20], 8);
        Log(WINTUN_LOG_INFO, L"Sending IPv4 ICMP echo request to 10.6.7.8 from 10.6.7.7");
}

static DWORD WINAPI
ReceivePackets(_Inout_ DWORD_PTR SessionPtr)
{
        WINTUN_SESSION_HANDLE Session = (WINTUN_SESSION_HANDLE)SessionPtr;
        HANDLE WaitHandles[] = { WintunGetReadWaitEvent(Session), QuitEvent };

        while (!HaveQuit)
        {
                DWORD PacketSize;
                BYTE* Packet = WintunReceivePacket(Session, &PacketSize);
                if (Packet)
                {
                        PrintPacket(Packet, PacketSize);
                        WintunReleaseReceivePacket(Session, Packet);
                }
                else
                {
                        DWORD LastError = GetLastError();
                        switch (LastError)
                        {
                        case ERROR_NO_MORE_ITEMS:
                                if (WaitForMultipleObjects(_countof(WaitHandles), WaitHandles, FALSE, INFINITE) == WAIT_OBJECT_0)
                                        continue;
                                return ERROR_SUCCESS;
                        default:
                                LogError(L"Packet read failed", LastError);
                                return LastError;
                        }
                }
        }
        return ERROR_SUCCESS;
}

static DWORD WINAPI
SendPackets(_Inout_ DWORD_PTR SessionPtr)
{
        WINTUN_SESSION_HANDLE Session = (WINTUN_SESSION_HANDLE)SessionPtr;
        while (!HaveQuit)
        {
                BYTE* Packet = WintunAllocateSendPacket(Session, 28);
                if (Packet)
                {
                        MakeICMP(Packet);
                        WintunSendPacket(Session, Packet);
                }
                else if (GetLastError() != ERROR_BUFFER_OVERFLOW)
                        return LogLastError(L"Packet write failed");

                switch (WaitForSingleObject(QuitEvent, 1000 /* 1 second */))
                {
                case WAIT_ABANDONED:
                case WAIT_OBJECT_0:
                        return ERROR_SUCCESS;
                }
        }
        return ERROR_SUCCESS;
}

static WINTUN_SESSION_HANDLE Session = NULL;
#define _AllocateSendPacket(len) WintunAllocateSendPacket(Session, len);
#define _SendPacket(pack) WintunSendPacket(Session, pack)


static int GetDefaultRouteIP(char ip[20])
{
        PMIB_IPFORWARDTABLE pIpForwardTable;
        DWORD dwSize = 0;   

        pIpForwardTable = (MIB_IPFORWARDTABLE*)malloc(sizeof(MIB_IPFORWARDTABLE));
        if (pIpForwardTable == NULL) {
                printf("Error allocating memory\n");
                return -1;
        }

        if (GetIpForwardTable(pIpForwardTable, &dwSize, 0) == ERROR_INSUFFICIENT_BUFFER) {
                free(pIpForwardTable);
                pIpForwardTable = (MIB_IPFORWARDTABLE*)malloc(dwSize);
                if (pIpForwardTable == NULL) {
                        printf("Error allocating memory\n");
                        return -1;
                }
        }

        if (GetIpForwardTable(pIpForwardTable, &dwSize, 0) == NO_ERROR) {
                int i;
                IF_INDEX ifIndx = 0;
                for (i = 0; i < (int)pIpForwardTable->dwNumEntries; i++) {
                        if ((pIpForwardTable->table[i].dwForwardDest == 0) && (pIpForwardTable->table[i].dwForwardType == MIB_IPROUTE_TYPE_INDIRECT)) {
                                ifIndx = pIpForwardTable->table[i].dwForwardIfIndex;
                                break;
                        }
                }
                for (i = 0; i < (int)pIpForwardTable->dwNumEntries; i++) {
                        if ((pIpForwardTable->table[i].dwForwardIfIndex == ifIndx) && (pIpForwardTable->table[i].dwForwardType == MIB_IPROUTE_TYPE_DIRECT)) {
                                struct in_addr IpAddr;
                                IpAddr.S_un.S_addr = (u_long)pIpForwardTable->table[i].dwForwardNextHop;
                                strcpy_s(ip, 20, inet_ntoa(IpAddr));
                                break;
                        }
                }

                free(pIpForwardTable);
                return 0;
        }
        else {
                free(pIpForwardTable);
                return -1;
        }
}

typedef struct _tun_socket_conext{
        BYTE* sendPacket;
        BYTE recvHead[4];
        DWORD recvLen;
        SOCKADDR_IN sockAddr;
        SOCKET hSock;
        WSAEVENT hEvent;
        WSANETWORKEVENTS netEvents;
}tun_socket_conext;

static void tun_socket_init(tun_socket_conext* ctx, int port) {
        memset(ctx, 0, sizeof(*ctx));
        ctx->sockAddr.sin_family = AF_INET;
        ctx->sockAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        ctx->sockAddr.sin_port = htons(port);
        ctx->hSock = INVALID_SOCKET;
        ctx->hEvent = WSACreateEvent();
        { WSADATA data; WSAStartup(MAKEWORD(2, 2), &data); }
}
static void tun_socket_exit(tun_socket_conext* ctx) {
        if (ctx->hSock != INVALID_SOCKET) {
                closesocket(ctx->hSock);
        }
        WSACloseEvent(ctx->hEvent);
        WSACleanup();
}
static void tun_socket_connect(tun_socket_conext *ctx) {
        ctx->hSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        WSAEventSelect(ctx->hSock, ctx->hEvent, FD_READ | FD_CONNECT | FD_CLOSE);
        connect(ctx->hSock, (SOCKADDR*)&(ctx->sockAddr), sizeof(SOCKADDR_IN));
}
static void tun_socket_do_event(tun_socket_conext* ctx) {
        ctx->netEvents.lNetworkEvents = 0;
        WSAEnumNetworkEvents(ctx->hSock, ctx->hEvent, &(ctx->netEvents));
 
        if (ctx->netEvents.lNetworkEvents & FD_READ) {
                if (ctx->recvLen < 4) {
                        int rv = recv(ctx->hSock, ctx->recvHead + ctx->recvLen, 4 - ctx->recvLen, 0);
                        if (rv > 0) {
                                ctx->recvLen += rv;
                                if (ctx->recvLen == 4) {
                                        rv = (ctx->recvHead[2] << 8) | ctx->recvHead[3];
                                        ctx->sendPacket = _AllocateSendPacket(rv);
                                        memcpy(ctx->sendPacket, ctx->recvHead, 4);
                                }
                        }
                }
                if (ctx->recvLen >= 4){
                        int tlen = (ctx->recvHead[2] << 8) | ctx->recvHead[3];
                        int rv = recv(ctx->hSock, ctx->sendPacket + ctx->recvLen, tlen - ctx->recvLen, 0);
                        if (rv > 0) {
                                ctx->recvLen += rv;
                                if (ctx->recvLen == tlen) {
                                        ctx->recvLen = 0;
                                        Log(WINTUN_LOG_INFO, L"WintunSendPacket: %d, ip check: %02x %02x", tlen, ctx->sendPacket[10], ctx->sendPacket[11]);
                                        _SendPacket(ctx->sendPacket);
                                }
                        }
                }
        }
        else if (ctx->netEvents.lNetworkEvents & FD_CONNECT) {
                if (ctx->netEvents.iErrorCode[FD_CONNECT_BIT] != 0) {
                        closesocket(ctx->hSock);
                        tun_socket_connect(ctx); // reconect
                }
        }    
        else if (ctx->netEvents.lNetworkEvents & FD_CLOSE) {
                closesocket(ctx->hSock);
                tun_socket_connect(ctx);
        }
}

static void _get_opts(int argc, char* argv[], const char* names[], char* outs[]) {
       for (int i = 0; i < (argc - 1); i++) {
                for (int j = 0; names[j]; j++) {
                        if (lstrcmpA(argv[i], names[j]) == 0) {
                                outs[j] = argv[++i];
                        }
                }
        }
 }

static BOOL PacketFliter(BYTE* Packet)
{
        if ((Packet[0] & 0xF0) == 0x40) // ipv4
        {
                BYTE* dst = Packet + 16;
                if ((dst[0] == 10) || ((dst[0] == 192) && (dst[1] == 168)) || ((dst[0] == 172) && ((dst[1] & 0xF0) == 0x10))) {
                        // 内网IP地址
                }
                else if (((dst[0] == 224) && (dst[1] == 0) && (dst[2] == 0)) || (dst[0] == 239)) {
                        // 预留的组播地址 | 本地管理组播地址
                }
                else {
                        return TRUE;
                }
        }
        return FALSE;
}

int tun_main(int argc, char* argv[], int sport)
{
        const char* ParamNames[] = {"-sport", "-saddr", "-name" , "-ip", "-defroute", NULL};
        char* ParamVals[5] = { NULL, NULL, NULL, NULL, NULL };
        _get_opts(argc, argv, ParamNames, ParamVals);

        tun_socket_conext sockCtx;
        tun_socket_init(&sockCtx, sport);

        if (ParamVals[0]) {
                sockCtx.sockAddr.sin_port = htons(atoi(ParamVals[0]));
        }
        if (ParamVals[1]) {
                sockCtx.sockAddr.sin_addr.s_addr = inet_addr(ParamVals[1]);
        }
    

        DWORD LastError;
        HMODULE Wintun = InitializeWintun();
        if (!Wintun)
        {
                LastError = LogError(L"Failed to initialize Wintun", GetLastError());
                goto cleanupSocket;
        }
        WintunSetLogger(ConsoleLogger);
        Log(WINTUN_LOG_INFO, L"Wintun library loaded");

        HaveQuit = FALSE;
        QuitEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (!QuitEvent)
        {
                LastError = LogError(L"Failed to create event", GetLastError());
                goto cleanupWintun;
        }
        if (!SetConsoleCtrlHandler(CtrlHandler, TRUE))
        {
                LastError = LogError(L"Failed to set console handler", GetLastError());
                goto cleanupQuit;
        }

        GUID TunGuid = { 0x3d48d650, 0xd8da, 0x40ee, { 0xb9, 0x8b, 0x2a, 0x6b, 0x41, 0xcf, 0xb7, 0x3a } };
        WCHAR TunName[64] = L"Tun1";
        if (ParamVals[2] != NULL)
        {
                MultiByteToWideChar(CP_ACP, 0, ParamVals[2], -1, TunName, 64);
        }
        WINTUN_ADAPTER_HANDLE Adapter = WintunCreateAdapter(TunName, L"WinTun", &TunGuid);
        if (!Adapter)
        {
                LastError = GetLastError();
                LogError(L"Failed to create adapter", LastError);
                goto cleanupQuit;
        }

        DWORD Version = WintunGetRunningDriverVersion();
        Log(WINTUN_LOG_INFO, L"Wintun v%u.%u loaded", (Version >> 16) & 0xff, (Version >> 0) & 0xff);

        char DefRouteIP[20];
        if (ParamVals[3] != NULL)
        {
                MIB_UNICASTIPADDRESS_ROW AddressRow;
                InitializeUnicastIpAddressEntry(&AddressRow);
                WintunGetAdapterLUID(Adapter, &AddressRow.InterfaceLuid);
                AddressRow.Address.Ipv4.sin_family = AF_INET;
                AddressRow.Address.Ipv4.sin_addr.S_un.S_addr = inet_addr(ParamVals[3]);
                AddressRow.OnLinkPrefixLength = 24; /* This is a /24 network */
                AddressRow.DadState = IpDadStatePreferred;
                LastError = CreateUnicastIpAddressEntry(&AddressRow);
                if (LastError != ERROR_SUCCESS && LastError != ERROR_OBJECT_ALREADY_EXISTS)
                {
                        LogError(L"Failed to set IP address", LastError);
                        goto cleanupAdapter;
                }

                // 配置route
                char cmd[256];
                for (int i = 0; i < (argc - 1); i++)
                {
                        if (lstrcmpA(argv[i], "-route") == 0)
                        {
                                wsprintfA(cmd, "route add %s/32 %s metric 5", argv[++i], ParamVals[3]);
                                system(cmd);
                        }
                }

                // 配置默认路由
                if (ParamVals[4] != NULL)
                {
                        lstrcpyA(DefRouteIP, ParamVals[4]);
                        if (lstrcmpA(DefRouteIP, "on") == 0)
                        {
                                GetDefaultRouteIP(DefRouteIP);
                        }

                        wsprintfA(cmd, "route add 0.0.0.0 mask 0.0.0.0 %s metric 6", ParamVals[3]);
                        system("route delete 0.0.0.0 mask 0.0.0.0");
                        system(cmd);
                }
        }

        Session = WintunStartSession(Adapter, 0x400000);
        if (!Session)
        {
                LastError = LogLastError(L"Failed to create adapter");
                goto cleanupAdapter;
        }

        //Log(WINTUN_LOG_INFO, L"Launching threads and mangling packets...");

        tun_socket_connect(&sockCtx);

        HANDLE WaitHandles[] = { WintunGetReadWaitEvent(Session), sockCtx.hEvent, QuitEvent };
        while (!HaveQuit)
        {
                DWORD PacketSize;
                BYTE* Packet = WintunReceivePacket(Session, &PacketSize);
                if (Packet)
                {
                        if (PacketFliter(Packet)) // TODO: test
                        {
                                Log(WINTUN_LOG_INFO, L"WintunReceivePacket: %d, ip check: %02x %02x", PacketSize, Packet[10], Packet[11]);
                                send(sockCtx.hSock, Packet, PacketSize, 0);
                        }
                }
                else
                {
                        LastError = GetLastError();
                        if (LastError == ERROR_NO_MORE_ITEMS)
                        {
                                DWORD Result = WaitForMultipleObjects(_countof(WaitHandles), WaitHandles, FALSE, INFINITE);
                                if (Result == WAIT_OBJECT_0) {
                                        continue;
                                }
                                else if (Result == WAIT_OBJECT_0 + 1) {
                                        tun_socket_do_event(&sockCtx);
                                        continue;
                                }
                        }
                        LogError(L"Packet read failed", LastError);
                        break;
            
                }
        }

//cleanupWorkers:
        HaveQuit = TRUE;
        SetEvent(QuitEvent);
        WintunEndSession(Session);
cleanupAdapter:
        if ((ParamVals[3] != NULL) && (ParamVals[4] != NULL))
        {
                char cmd[256];
                wsprintfA(cmd, "route add 0.0.0.0 mask 0.0.0.0 %s metric 6", DefRouteIP);
                system("route delete 0.0.0.0 mask 0.0.0.0");
                system(cmd);
        }
        WintunCloseAdapter(Adapter);
cleanupQuit:
        SetConsoleCtrlHandler(CtrlHandler, FALSE);
        CloseHandle(QuitEvent);
cleanupWintun:
        FreeLibrary(Wintun);
cleanupSocket:
        tun_socket_exit(&sockCtx);
        return LastError;
}
#endif // #ifdef _WIN32
