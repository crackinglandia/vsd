/* 
$Id: vsd_hdrs.h 18 2012-04-01 19:27:27Z crackinglandia $

Virtual Section Dumper v2.0 x86

Copyright (C) 2012 +NCR/CRC! [ReVeRsEr] http://crackinglandia.blogspot.com

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <windows.h>
#include <Commctrl.h>
#include <stdio.h>
#include <psapi.h>
#include <Shlwapi.h>
#include <Strsafe.h>
#include <Windowsx.h>
#include <tlhelp32.h>

/* 
	Comment this header ("stdafx.h") to avoid the ComCtl32.dll version 6
	issue whith the LVS_EX_GRIDLINES
*/
//#include "stdafx.h"

#include "resource.h"

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Comdlg32.lib")
#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Advapi32.lib")

typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
LPFN_ISWOW64PROCESS fnIsWow64Process;

typedef LONG NTSTATUS;
typedef LONG KPRIORITY;

typedef enum _KWAIT_REASON
{
         Executive = 0,
         FreePage = 1,
         PageIn = 2,
         PoolAllocation = 3,
         DelayExecution = 4,
         Suspended = 5,
         UserRequest = 6,
         WrExecutive = 7,
         WrFreePage = 8,
         WrPageIn = 9,
         WrPoolAllocation = 10,
         WrDelayExecution = 11,
         WrSuspended = 12,
         WrUserRequest = 13,
         WrEventPair = 14,
         WrQueue = 15,
         WrLpcReceive = 16,
         WrLpcReply = 17,
         WrVirtualMemory = 18,
         WrPageOut = 19,
         WrRendezvous = 20,
         Spare2 = 21,
         Spare3 = 22,
         Spare4 = 23,
         Spare5 = 24,
         WrCalloutStack = 25,
         WrKernel = 26,
         WrResource = 27,
         WrPushLock = 28,
         WrMutex = 29,
         WrQuantumEnd = 30,
         WrDispatchInt = 31,
         WrPreempted = 32,
         WrYieldExecution = 33,
         WrFastMutex = 34,
         WrGuardedMutex = 35,
         WrRundown = 36,
         MaximumWaitReason = 37
} KWAIT_REASON;

#define OPENPROCESS_ERROR 0xCAFECAFE
#define READPROCESSMEMORY_ERROR 0xD00FD00F
#define VIRTULALLOC_ERROR 0xCACAF0FA
#define CREATEFILE_ERROR 0xDEADBEEF
#define WRITEFILE_ERROR 0xC0CAC0CA

#define SAVEDIALOGNOCHOICE 0xFECAC0C0

#define RTN_OK 1
#define RTN_USAGE 0
#define RTN_ERROR 13

#define MAX_COLS 4
#define MAX_PIDS 1024
#define MAX_MODULES 1024
#define MAX_COLSREG 5

#define IDM_DUMP_REGION 10000
#define IDM_DUMP_FULL 10006
#define IDM_DUMP_PARTIAL 10007
#define IDM_COPY2CLIPBOARD 10002
#define IDM_SELECTALL 10003
#define IDM_REFRESH 10004
#define IDM_DELPROCESS 10005
#define IDM_PATCH_PROCESS 10106
#define IDM_LIST_MODULES 10123
#define IDM_LIST_HANDLES 10008
#define IDM_LIST_THREADS 10009
#define IDM_RESUME_THREAD 10101
#define IDM_SUSPEND_THREAD 10102
#define IDM_TERMINATE_THREAD 10103
#define IDM_REFRESH_THREAD_LIST 10104

//#define HOTKEY_CTRL_C 12345
//#define HOTKEY_CTRL_A 12346
//#define HOTKEY_CTRL_R 12335
//#define HOTKEY_SHIFT_DEL 12337
//
//#define HOTKEY_CTRL_C2 0xDEAD
//#define HOTKEY_CTRL_A2 0xBEEF

//#define CTRL_C 0x43
//#define CTRL_A 0x41
//#define CTRL_R 0x52

#define NO_SORT 0
#define SORT_ASCENDING 1
#define SORT_DESCENDING 2

#define PATH_COLUMN 0
#define PATH_SORT_ASCENDING 1
#define PATH_SORT_DESCENDING 2

#define PID_COLUMN 1
#define PID_SORT_ASCENDING 3
#define PID_SORT_DESCENDING 4

#define IB_COLUMN 2
#define IB_SORT_ASCENDING 5
#define IB_SORT_DESCENDING 6

#define IZ_COLUMN 3
#define IZ_SORT_ASCENDING 7
#define IZ_SORT_DESCENDING 8

#define ADDR_COLUMN 0
#define ADDR_SORT_ASCENDING 1
#define ADDR_SORT_DESCENDING 2

#define SIZE_COLUMN 1
#define SIZE_SORT_ASCENDING 3
#define SIZE_SORT_DESCENDING 4

#define PROTECT_COLUMN 2
#define PROTECT_SORT_ASCENDING 5
#define PROTECT_SORT_DESCENDING 6

#define STATE_COLUMN 3
#define STATE_SORT_ASCENDING 7
#define STATE_SORT_DESCENDING 8

#define TYPE_COLUMN 4
#define TYPE_SORT_ASCENDING 9
#define TYPE_SORT_DESCENDING 10

#define DUMPFULL 0xF000
#define DUMPPARTIAL 0xFF00
#define DUMPREGION 0xFFF0

#define HANDLE_TYPE_COL 0
#define HANDLE_TYPE_COL_SORT_ASCENDING 1
#define HANDLE_TYPE_COL_SORT_DESCENDING 2

#define HANDLE_NAME_COL 1
#define HANDLE_NAME_COL_SORT_ASCENDING 3
#define HANDLE_NAME_COL_SORT_DESCENDING 4

#define HANDLE_COL 2
#define HANDLE_COL_SORT_ASCENDING 5
#define HANDLE_COL_SORT_DESCENDING 6

#define MODULE_NAME_COL 0
#define MODULE_NAME_COL_SORT_ASCENDING 1
#define MODULE_NAME_COL_SORT_DESCENDING 2

#define MODULE_IMAGEBASE_COL 1
#define MODULE_IMAGEBASE_COL_SORT_ASCENDING 3
#define MODULE_IMAGEBASE_COL_SORT_DESCENDING 4

#define MODULE_IMAGESIZE_COL 2
#define MODULE_IMAGESIZE_COL_SORT_ASCENDING 5
#define MODULE_IMAGESIZE_COL_SORT_DESCENDING 6

#define THREAD_ID_COL 0
#define THREAD_ID_SORT_ASCENDING 1
#define THREAD_ID_SORT_DESCENDING 2

#define THREAD_PRIORITY_COL 1
#define THREAD_PRIORITY_SORT_ASCENDING 3
#define THREAD_PRIORITY_SORT_DESCENDING 4

#define THREAD_TEB_COL 2
#define THREAD_TEB_SORT_ASCENDING 5
#define THREAD_TEB_SORT_DESCENDING 6

#define THREAD_STARTADDRESS_COL 3
#define THREAD_START_SORT_ASCENDING 7
#define THREAD_START_SORT_DESCENDING 8

#define THREAD_STATE_COL 4
#define THREAD_STATE_SORT_ASCENDING 9
#define THREAD_STATE_SORT_DESCENDING 10

#define NT_SUCCESS(x) ((x) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

#define MAX_SPIN_POS 255
#define MIN_SPIN_POS 1

#define MAKESPINRANGE(x, y) ((x << 16) | y)

#define SUSPEND_THREAD_ACTION 0x5566
#define TERMINATE_THREAD_ACTION 0x6677
#define RESUME_THREAD_ACTION  0x7788

#define SystemHandleInformation 16
#define ObjectBasicInformation 0
#define SystemProcessesAndThreadsInformation 5
#define ObjectNameInformation 1
#define ObjectTypeInformation 2
#define ThreadQuerySetWin32StartAddress 9

typedef struct _UNICODE_STRING

{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

// http://www.nirsoft.net/kernel_struct/vista/CLIENT_ID.html
typedef struct _CLIENT_ID
{
     DWORD UniqueProcess;
     DWORD UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

// http://msdn.microsoft.com/en-us/library/gg750724%28v=prot.10%29.aspx
typedef struct {
  LARGE_INTEGER KernelTime;
  LARGE_INTEGER UserTime;
  LARGE_INTEGER CreateTime;
  ULONG WaitTime;
  PVOID StartAddress;
  CLIENT_ID ClientId;
  KPRIORITY Priority;
  KPRIORITY BasePriority;
  ULONG ContextSwitches;
  ULONG ThreadState;
  ULONG WaitReason;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

// from http://web.archive.org/web/20080821182048/http://www.alexfedotov.com/samples/threads.asp
typedef struct _VM_COUNTERS {
    SIZE_T	    PeakVirtualSize;
    SIZE_T	    VirtualSize;
    ULONG	    PageFaultCount;
    SIZE_T	    PeakWorkingSetSize;
    SIZE_T	    WorkingSetSize;
    SIZE_T	    QuotaPeakPagedPoolUsage;
    SIZE_T	    QuotaPagedPoolUsage;
    SIZE_T	    QuotaPeakNonPagedPoolUsage;
    SIZE_T	    QuotaNonPagedPoolUsage;
    SIZE_T	    PagefileUsage;
    SIZE_T	    PeakPagefileUsage;
} VM_COUNTERS;

// http://web.archive.org/web/20080821182048/http://www.alexfedotov.com/samples/threads.asp
typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG			NextEntryDelta;
    ULONG			ThreadCount;
    ULONG			Reserved1[6];
    LARGE_INTEGER   CreateTime;
    LARGE_INTEGER   UserTime;
    LARGE_INTEGER   KernelTime;
    UNICODE_STRING  ProcessName;
    KPRIORITY	    BasePriority;
    ULONG			ProcessId;
    ULONG			InheritedFromProcessId;
    ULONG			HandleCount;
    ULONG			Reserved2[2];
    VM_COUNTERS	    VmCounters;
    IO_COUNTERS	    IoCounters;
    SYSTEM_THREAD_INFORMATION  Threads[1];
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

typedef NTSTATUS (NTAPI *_NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

typedef NTSTATUS (NTAPI *_NtDuplicateObject)(
    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG Attributes,
    ULONG Options
    );

typedef NTSTATUS (NTAPI *_NtQueryObject)(
    HANDLE ObjectHandle,
    ULONG ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
    );

typedef NTSTATUS (NTAPI *_NtQueryInformationThread)(
	HANDLE ThreadHandle,
	DWORD ThreadInformationClass,
	PVOID ThreadInformation, 
	ULONG ThreadInformationLength, 
	PULONG ReturnLength
	);

typedef struct _SYSTEM_HANDLE
{
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG HandleCount;
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef enum _POOL_TYPE
{
    NonPagedPool,
    PagedPool,
    NonPagedPoolMustSucceed,
    DontUseThisType,
    NonPagedPoolCacheAligned,
    PagedPoolCacheAligned,
    NonPagedPoolCacheAlignedMustS
} POOL_TYPE, *PPOOL_TYPE;

typedef struct _OBJECT_TYPE_INFORMATION
{
    UNICODE_STRING Name;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccess;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    USHORT MaintainTypeList;
    POOL_TYPE PoolType;
    ULONG PagedPoolUsage;
    ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

typedef struct _PEB_FREE_BLOCK {
	struct _PEB_FREE_BLOCK	*Next;
	ULONG					Size;
} PEB_FREE_BLOCK, *PPEB_FREE_BLOCK;

typedef LPVOID *PPVOID;

typedef void (*PPEBLOCKROUTINE)( PVOID PebLock ); 

typedef struct _PEB_LDR_DATA {
	ULONG					Length;
	BOOL					Initialized;
	PVOID					SsHandle;
	LIST_ENTRY				InLoadOrderModuleList;
	LIST_ENTRY				InMemoryOrderModuleList;
	LIST_ENTRY				InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;


typedef struct _SECTION_IMAGE_INFORMATION {
	PVOID					EntryPoint;
	ULONG					StackZeroBits;
	ULONG					StackReserved;
	ULONG					StackCommit;
	ULONG					ImageSubsystem;
	WORD					SubsystemVersionLow;
	WORD					SubsystemVersionHigh;
	ULONG					Unknown1;
	ULONG					ImageCharacteristics;
	ULONG					ImageMachineType;
	ULONG					Unknown2[3];
} SECTION_IMAGE_INFORMATION, *PSECTION_IMAGE_INFORMATION;

typedef struct _RTL_USER_PROCESS_INFORMATION {
	ULONG					Size;
	HANDLE					ProcessHandle;
	HANDLE					ThreadHandle;
	CLIENT_ID				ClientId;
	SECTION_IMAGE_INFORMATION ImageInformation;
} RTL_USER_PROCESS_INFORMATION, *PRTL_USER_PROCESS_INFORMATION;

typedef struct _RTL_DRIVE_LETTER_CURDIR {
	USHORT					Flags;
	USHORT					Length;
	ULONG					TimeStamp;
	UNICODE_STRING			DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	ULONG					MaximumLength;
	ULONG					Length;
	ULONG					Flags;
	ULONG					DebugFlags;
	PVOID					ConsoleHandle;
	ULONG					ConsoleFlags;
	HANDLE					StdInputHandle;
	HANDLE					StdOutputHandle;
	HANDLE					StdErrorHandle;
	UNICODE_STRING			CurrentDirectoryPath;
	HANDLE					CurrentDirectoryHandle;
	UNICODE_STRING			DllPath;
	UNICODE_STRING			ImagePathName;
	UNICODE_STRING			CommandLine;
	PVOID					Environment;
	ULONG					StartingPositionLeft;
	ULONG					StartingPositionTop;
	ULONG					Width;
	ULONG					Height;
	ULONG					CharWidth;
	ULONG					CharHeight;
	ULONG					ConsoleTextAttributes;
	ULONG					WindowFlags;
	ULONG					ShowWindowFlags;
	UNICODE_STRING			WindowTitle;
	UNICODE_STRING			DesktopName;
	UNICODE_STRING			ShellInfo;
	UNICODE_STRING			RuntimeData;
	RTL_DRIVE_LETTER_CURDIR DLCurrentDirectory[0x20];
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB {
	BOOLEAN                 InheritedAddressSpace;
	BOOLEAN                 ReadImageFileExecOptions;
	BOOLEAN                 BeingDebugged;
	BOOLEAN                 Spare;
	HANDLE                  Mutant;
	PVOID                   ImageBaseAddress;
	PPEB_LDR_DATA           LoaderData;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID                   SubSystemData;
	PVOID                   ProcessHeap;
	PVOID                   FastPebLock;
	PPEBLOCKROUTINE         FastPebLockRoutine;
	PPEBLOCKROUTINE         FastPebUnlockRoutine;
	ULONG                   EnvironmentUpdateCount;
	PPVOID                  KernelCallbackTable;
	PVOID                   EventLogSection;
	PVOID                   EventLog;
	PPEB_FREE_BLOCK         FreeList;
	ULONG                   TlsExpansionCounter;
	PVOID                   TlsBitmap;
	ULONG                   TlsBitmapBits[0x2];
	PVOID                   ReadOnlySharedMemoryBase;
	PVOID                   ReadOnlySharedMemoryHeap;
	PPVOID                  ReadOnlyStaticServerData;
	PVOID                   AnsiCodePageData;
	PVOID                   OemCodePageData;
	PVOID                   UnicodeCaseTableData;
	ULONG                   NumberOfProcessors;
	ULONG                   NtGlobalFlag;
	BYTE                    Spare2[0x4];
	LARGE_INTEGER           CriticalSectionTimeout;
	ULONG                   HeapSegmentReserve;
	ULONG                   HeapSegmentCommit;
	ULONG                   HeapDeCommitTotalFreeThreshold;
	ULONG                   HeapDeCommitFreeBlockThreshold;
	ULONG                   NumberOfHeaps;
	ULONG                   MaximumNumberOfHeaps;
	PPVOID                  *ProcessHeaps;
	PVOID                   GdiSharedHandleTable;
	PVOID                   ProcessStarterHelper;
	PVOID                   GdiDCAttributeList;
	PVOID                   LoaderLock;
	ULONG                   OSMajorVersion;
	ULONG                   OSMinorVersion;
	ULONG                   OSBuildNumber;
	ULONG                   OSPlatformId;
	ULONG                   ImageSubSystem;
	ULONG                   ImageSubSystemMajorVersion;
	ULONG                   ImageSubSystemMinorVersion;
	ULONG                   GdiHandleBuffer[0x22];
	ULONG                   PostProcessInitRoutine;
	ULONG                   TlsExpansionBitmap;
	BYTE                    TlsExpansionBitmapBits[0x80];
	ULONG                   SessionId;
} PEB, *PPEB;

typedef struct _TEB {
	NT_TIB					Tib;
	PVOID					EnvironmentPointer;
	CLIENT_ID				Cid;
	PVOID					ActiveRpcInfo;
	PVOID					ThreadLocalStoragePointer;
	PPEB					Peb;
	ULONG					LastErrorValue;
	ULONG					CountOfOwnedCriticalSections;
	PVOID					CsrClientThread;
	PVOID					Win32ThreadInfo;
	ULONG					Win32ClientInfo[0x1F];
	PVOID					WOW32Reserved;
	ULONG					CurrentLocale;
	ULONG					FpSoftwareStatusRegister;
	PVOID					SystemReserved1[0x36];
	PVOID					Spare1;
	ULONG					ExceptionCode;
	ULONG					SpareBytes1[0x28];
	PVOID					SystemReserved2[0xA];
	ULONG					GdiRgn;
	ULONG					GdiPen;
	ULONG					GdiBrush;
	CLIENT_ID				RealClientId;
	PVOID					GdiCachedProcessHandle;
	ULONG					GdiClientPID;
	ULONG					GdiClientTID;
	PVOID					GdiThreadLocaleInfo;
	PVOID					UserReserved[5];
	PVOID					GlDispatchTable[0x118];
	ULONG					GlReserved1[0x1A];
	PVOID					GlReserved2;
	PVOID					GlSectionInfo;
	PVOID					GlSection;
	PVOID					GlTable;
	PVOID					GlCurrentRC;
	PVOID					GlContext;
	NTSTATUS				LastStatusValue;
	UNICODE_STRING			StaticUnicodeString;
	WCHAR					StaticUnicodeBuffer[0x105];
	PVOID					DeallocationStack;
	PVOID					TlsSlots[0x40];
	LIST_ENTRY				TlsLinks;
	PVOID					Vdm;
	PVOID					ReservedForNtRpc;
	PVOID					DbgSsReserved[0x2];
	ULONG					HardErrorDisabled;
	PVOID					Instrumentation[0x10];
	PVOID					WinSockData;
	ULONG					GdiBatchCount;
	ULONG					Spare2;
	ULONG					Spare3;
	ULONG					Spare4;
	PVOID					ReservedForOle;
	ULONG					WaitingOnLoaderLock;
	PVOID					StackCommit;
	PVOID					StackCommitMax;
	PVOID					StackReserved;
} TEB, *PTEB;

DWORD GetSuspendThreadCount(HANDLE hThread);
DWORD GetResumeThreadCount(HANDLE hThread);
DWORD GetThreadWin32StartAddress(HANDLE hThread);

LPVOID GetThreadTebAddress(DWORD ThreadId);

const char* DwordToHex(DWORD value);
const char* GetWaitReasonString(unsigned long);

// global function declarations
bool HexToBin(char*, unsigned long, unsigned long, char*);
void BinToHex(char*, unsigned long, char*);
void InitCommonCtrlsEx(void);
void CreateColumns(HWND);
void EnumRegions(HWND);
void CreateColumnsRegionLV(HWND);
void CreateColumnsHandlesLV(HWND);
void CreateColumnsModulesLV(HWND);
void CreateColumnsThreadsLV(HWND);
void ShowAboutInfo(HWND);
void SetHotKey(WORD);
void CopyDataToClipBoard(HWND, int);
void MySetClipboardData(void*, SIZE_T);
void SelectAllItems(HWND);
void UpdatelParam(HWND);
void SortProcListView(HWND, int);
void SortRegionsListView(HWND, int);
void ValidateResult(int);
void RefreshLV(HWND, HWND);
void SortHandlesListView(HWND, int);
void SortThreadsListView(HWND, int);
void SortModulesListView(HWND, int);
void RefreshThreadsLV(HWND);
void MyTerminateThread(HWND, int);
void MySuspendThread(HWND, int);
void MyResumeThread(HWND, int);
void DoAction(HWND, int);

// functions to help in debugging
void DebugMe(char* msgText);
void DebugShowDword(unsigned long);

int EnumProcessHandles(HWND);
int MyEnumProcessModules(HWND, HWND);
int EnumProcessThreads(HWND);
int MyDumpModuleFunction(void*, DWORD, char*, int, BOOL, BOOL, HWND);
int DumpMemoryRegion(void*, DWORD, int, BOOL, BOOL, HWND);
int ListView_GetPidFromItem(HWND, int);
int AdjustPrivileges(void);

int CALLBACK ListViewProcessesCompareProc(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort);
int CALLBACK ListViewRegionsCompareProc(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort);
int CALLBACK HandlesCompareProc(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort);
int CALLBACK ModulesCompareProc(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort);
int CALLBACK ThreadsCompareProc(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort);

BOOL CALLBACK EnumModulesDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
BOOL CALLBACK EnumHandlesDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
BOOL CALLBACK AppDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
BOOL CALLBACK DumpRegionProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
BOOL CALLBACK PartialDumpProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
BOOL CALLBACK ThreadsDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
BOOL CALLBACK PatchProcessDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
BOOL CALLBACK Filter(HWND, UINT, WPARAM, LPARAM);

BOOL IsWow64(HANDLE hProc);
BOOL IsValidHexString(char*);
BOOL ListProcesses(HWND, HWND);
BOOL SetPrivilege(HANDLE hToken, LPCTSTR Privilege, BOOL bEnablePrivilege);
BOOL PastePEHeader(HANDLE, DWORD, char*);
BOOL FixHeader(HANDLE, DWORD, char*);

HWND PopulateRegionLV(HWND);
HWND PopulateThreadsLV(HWND);
HWND MyGetWindowOwner(HWND);
HWND PopulateListView(HWND);
HWND PopulateModulesLV(HWND);

PVOID GetLibraryProcAddress(PSTR LibraryName, PSTR ProcName);

// global variables
int item;
BOOL RunningOnWow64, HasPrivileges, bGlobalPastePEHeader, bGlobalFixHeader, DumpingModule = FALSE;
HMODULE hMods[MAX_MODULES];
HWND hList, hRegionsLV, hThreadsLV, hHandlesLV, hModulesLV, ExcludeWow64CheckBox = NULL;
HWND hAddrToPatch, hNroBytesToPatch, hOriginalBytes, hNewBytes;
HMENU hMainMenu, hViewSubMenu, hDumpModuleSubMenu, hDumpSubMenu, hCopy2Clip, hHandlesCopy2Clip, hModulesCopy2Clip, hThreadMenu;
POINT pt, pt2;
ACCEL MyAccel;
HACCEL hAccel;
HINSTANCE hGlobalInstance;
DWORD iGlobalPid = -1, RegionAddr = -1, RegionSize = -1, pIds[MAX_PIDS];
char szGlobalModuleName[MAX_PATH], szCaption[MAX_PATH];
LONG wndproc;

// global state variables for sorting
int PathSortOrder = 0, PidSortOrder = 0, IbSortOrder = 0, IzSortOrder = 0;
int AddrSortOrder = 0, SizeSortOrder = 0, ProtectSortOrder = 0, StateSortOrder = 0, TypeSortOrder = 0;
int HandleTypeSortOrder = 0, HandleNameSortOrder = 0, HandleSortOrder = 0;
int ModuleNameSortOrder = 0, ModuleImageBaseSortOrder = 0, ModuleImageSizeSortOrder = 0;
int ThreadIdSortOrder = 0, ThreadPrioritySortOrder = 0, ThreadTebSortOrder = 0, ThreadStartSortOrder = 0, ThreadStateSortOrder = 0;

_NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetLibraryProcAddress("ntdll.dll", "NtQuerySystemInformation");
_NtDuplicateObject NtDuplicateObject = (_NtDuplicateObject)GetLibraryProcAddress("ntdll.dll", "NtDuplicateObject");
_NtQueryObject NtQueryObject = (_NtQueryObject)GetLibraryProcAddress("ntdll.dll", "NtQueryObject");
_NtQueryInformationThread NtQueryInformationThread = (_NtQueryInformationThread)GetLibraryProcAddress("ntdll.dll", "NtQueryInformationThread");