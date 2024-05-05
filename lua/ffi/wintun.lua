local require = require
local string_sub = string.sub
local ffi = require "ffi"
--local ffi_gc = ffi.gc
local ffi_new = ffi.new
local ffi_string = ffi.string
local ffi_copy = ffi.copy
local ffi_NULL = ffi.NULL
local ffi_cast = ffi.cast
local bit = require("bit")


local _C = ffi.load("wintun.dll")
local _C_Kernel32 = ffi.load("Kernel32.dll")

ffi.cdef[[
typedef enum
{
    WINTUN_LOG_INFO, /**< Informational */
    WINTUN_LOG_WARN, /**< Warning */
    WINTUN_LOG_ERR   /**< Error */
} WINTUN_LOGGER_LEVEL;

typedef unsigned char BYTE;
typedef short* LPWSTR;
typedef const short* LPCWSTR;
typedef unsigned int DWORD;
typedef unsigned long long DWORD64;
typedef void* HANDLE;
typedef struct _NET_LUID NET_LUID;
typedef struct _WINTUN_ADAPTER *WINTUN_ADAPTER_HANDLE;
typedef struct _TUN_SESSION *WINTUN_SESSION_HANDLE;
typedef void (__stdcall *WINTUN_LOGGER_CALLBACK)(WINTUN_LOGGER_LEVEL Level, DWORD64 Timestamp, LPCWSTR Message);

WINTUN_ADAPTER_HANDLE __stdcall WintunCreateAdapter(LPCWSTR Name, LPCWSTR TunnelType, const char *RequestedGUID);
void __stdcall WintunCloseAdapter( WINTUN_ADAPTER_HANDLE Adapter);
void __stdcall WintunGetAdapterLUID(WINTUN_ADAPTER_HANDLE Adapter, NET_LUID *Luid);
DWORD __stdcall WintunGetRunningDriverVersion(void);
int __stdcall WintunDeleteDriver(void);
void __stdcall WintunSetLogger(WINTUN_LOGGER_CALLBACK NewLogger);
WINTUN_SESSION_HANDLE __stdcall WintunStartSession(WINTUN_ADAPTER_HANDLE Adapter, DWORD Capacity);
void __stdcall WintunEndSession(WINTUN_SESSION_HANDLE Session);
HANDLE __stdcall WintunGetReadWaitEvent(WINTUN_SESSION_HANDLE Session);
BYTE * __stdcall WintunReceivePacket(WINTUN_SESSION_HANDLE Session, DWORD *PacketSize);
void __stdcall WintunReleaseReceivePacket(WINTUN_SESSION_HANDLE Session, const BYTE *Packet);
BYTE * __stdcall WintunAllocateSendPacket(WINTUN_SESSION_HANDLE Session, DWORD PacketSize);
void __stdcall WintunSendPacket(WINTUN_SESSION_HANDLE Session, const BYTE *Packet);

DWORD __stdcall GetLastError(void);
DWORD __stdcall WaitForSingleObject(HANDLE hHandle, DWORD  dwMilliseconds);
int __stdcall MultiByteToWideChar(unsigned int CodePage, DWORD dwFlags, const char* lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);
]]

local function a2w(s)
	local wlen = _C_Kernel32.MultiByteToWideChar(65001, 0, s, #s, ffi_NULL, 0)
	local wbuf = ffi_new("short[?]", wlen + 1)
	_C_Kernel32.MultiByteToWideChar(65001, 0, s, #s, wbuf, wlen)
	wbuf[wlen] = 0
	return wbuf
end

local function print_bytes(msg, buf, blen)
	io.write(msg, string.format("(%d): ", blen))	
	for i=0,blen-1 do
		io.write(string.format("%02X", buf[i]))
	end
	io.write("\n")
end


local tunGUID1 = "\xb7\xe9\xb1\xff\xdb\x15\x34\x49\xa0\xe6\xf2\x9a\x10\x80\xb2\xfa"


local function IPChecksum(Buffer, count)
	local sum = 0
	if (bit.band(count, 1) == 1) then
		sum = Buffer[count-1]
		count = count -1
	end
	
	for i=0, count-1, 2 do
		sum = sum + Buffer[i] + (Buffer[i+1] * 256)
	end
	
	while( sum > 0xFFFF )  do
		sum = bit.rshift(sum, 16) + bit.band(sum, 0xFFFF)
	end

    return bit.band(bit.bnot(sum), 0xFFFF)
end

local function MakeICMP(Packet)
	--ffi.fill
	Packet[0] = 0x46;
	Packet[1] = 0x00;
	Packet[2] = 0x00;
	Packet[3] = 0x28;
	Packet[4] = 0xBD;
	Packet[5] = 0xE0;
	Packet[6] = 0x00;
	Packet[7] = 0x00;
	Packet[8] = 0x01;
	Packet[9] = 0x02;
	Packet[10] = 0x00;
	Packet[11] = 0x00;
	ffi.copy(Packet+12, "\xA9\xFE\x7A\x61\xE0\x00\x00\x16")
    IPChecksum(Packet, 20)
	
    --Packet[20] = 8;
    --*(USHORT *)&Packet[22] = IPChecksum(&Packet[20], 8);
end



local hAdapter = _C.WintunCreateAdapter(a2w("tun2vless"), a2w("Wintun"), tunGUID1)
if (hAdapter == ffi_NULL) then
	print("call WintunCreateAdapter fail! GetLastError()=", _C_Kernel32.GetLastError())
end
 
local hSession = _C.WintunStartSession(hAdapter, 0x400000) --4M
if (hSession == ffi_NULL) then
	print("call WintunStartSession fail! GetLastError()=", _C_Kernel32.GetLastError())
end
 
local hEvent = _C.WintunGetReadWaitEvent(hSession)
while (true) do
	local packetSize = ffi_new("unsigned int[?]", 1)
	local packet = _C.WintunReceivePacket(hSession, packetSize)
	if (packet == ffi_NULL) then
		local lastError = _C_Kernel32.GetLastError()
		if (lastError == 259) then -- ERROR_NO_MORE_ITEMS
			local rv = _C_Kernel32.WaitForSingleObject(hEvent, -1)
			
			--[[local tt = "\x45\x00\x00\x00\x00\x00\x00\x00\xFF\x01\x99\xE2\x0A\x06\x07\x08\x0A\x06\x07\x07\x08\x00\xF7\xFF\x00\x00\x00\x00"
			local Packet = _C.WintunAllocateSendPacket(hSession, 28)
			ffi.copy(Packet, tt)
			print_bytes("Packet", Packet, 28)
			rv = _C.WintunSendPacket(hSession, Packet)
			print("WintunSendPacket:", rv)]]
		else
			print("lastError:", lastError)
		end
	else
		if bit.band(packet[0], 0xF0) == 0x40 then --IPV4
			if packet[9] == 17 then -- UDP
				local dport = packet[22] * 256 + packet[23]
				-- 224.0.0.251, 5353 --mDNS
				if (packet[16] == 0xE0 and packet[17] == 0x00 and packet[18] == 0x00 and packet[19] == 0xFB and packet[22] == 0x14 and packet[23] == 0xE9) then
				-- 224.0.0.252, 5355 --LLMNR（本地链路组播名称解析）14EB
				elseif(packet[16] == 0xE0 and packet[17] == 0x00 and packet[18] == 0x00 and packet[19] == 0xFC and packet[22] == 0x14 and packet[23] == 0xEB) then
				-- 10.255.255.255, 137/138 --局域网中提供计算机的名字或IP地址查询服务(NetBIOS)
				elseif(packet[17] == 0xFF and packet[18] == 0xFF and packet[19] == 0xFF and packet[22] == 0x00 and (packet[23] == 0x89 or packet[23] == 0x8A)) then
				-- 239.255.255.250,1900 --UPnp服务(ssdp:discover)
				elseif(packet[16] == 0xEF and packet[17] == 0xFF and packet[18] == 0xFF and packet[19] == 0xFA and packet[22] == 0x07 and packet[23] == 0x6C) then
				-- 239.255.255.250,3702 --ONVIF(Probe)
				elseif(packet[16] == 0xEF and packet[17] == 0xFF and packet[18] == 0xFF and packet[19] == 0xFA and packet[22] == 0x0E and packet[23] == 0x76) then
				else
					print_bytes("receive packet(proto=11/UDP)", packet, packetSize[0])
				end
			else
				print_bytes(string.format("receive packet(proto=%d)", packet[9]), packet, packetSize[0])
			end
		end
		_C.WintunReleaseReceivePacket(hSession, packet)
		--break
	end
 end      

_C.WintunEndSession(hSession)
_C.WintunCloseAdapter(hAdapter)
 
print(hSession)