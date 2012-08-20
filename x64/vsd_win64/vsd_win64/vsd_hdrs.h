/*
$Id: vsd_hdrs.h 13 2012-02-28 02:59:08Z crackinglandia $

Virtual Section Dumper v1.0 x64

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

typedef SIZE_T (WINAPI *MYVIRTUALQUERYEX) (HANDLE, LPCVOID, PMEMORY_BASIC_INFORMATION64, SIZE_T);
MYVIRTUALQUERYEX myVirtualQueryEx;

typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
LPFN_ISWOW64PROCESS fnIsWow64Process;

#define OPENPROCESS_ERROR 0xCAFECAFE
#define READPROCESSMEMORY_ERROR 0xD00FD00F
#define VIRTULALLOC_ERROR 0xCACAF0FA
#define CREATEFILE_ERROR 0xDEADBEEF
#define WRITEFILE_ERROR 0xC0CAC0CA

#define SAVEDIALOGNOCHOICE 0xFECAC0C0

#define RTN_OK 1
#define RTN_USAGE 0
#define RTN_ERROR 13

#define MAX_COLS 5
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

//#define HOTKEY_CTRL_C 12345
//#define HOTKEY_CTRL_A 12346
//#define HOTKEY_CTRL_R 12335
//#define HOTKEY_SHIFT_DEL 12337
//
//#define HOTKEY_CTRL_C2 0xDEAD
//#define HOTKEY_CTRL_A2 0xBEEF
//
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

#define ITYPE_COLUMN 4
#define ITYPE_SORT_ASCENDING 9
#define ITYPE_SORT_DESCENDING 10

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

// global function declarations
void InitCommonCtrlsEx(void);
void CreateColumns(HWND);
void EnumRegions(HWND);
void CreateColumnsRegionLV(HWND);
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

int DumpMemoryRegion(void*, ULONGLONG, int, BOOL, BOOL, HWND);
int ListView_GetPidFromItem(HWND, int);
int AdjustPrivileges(void);
int CALLBACK ListViewProcessesCompareProc(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort);
int CALLBACK ListViewRegionsCompareProc(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort);

BOOL CALLBACK AppDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
BOOL CALLBACK DumpRegionProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
BOOL CALLBACK PartialDumpProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);

BOOL IsWow64(HANDLE hProc);
BOOL IsValidHexString(char*);
BOOL ListProcesses(HWND, HWND);
BOOL SetPrivilege(HANDLE hToken, LPCTSTR Privilege, BOOL bEnablePrivilege);
BOOL PastePEHeader(HANDLE, ULONGLONG, char*);
BOOL FixHeader(HANDLE, ULONGLONG, char*);

HWND PopulateRegionLV(HWND);
HWND MyGetWindowOwner(HWND);
HWND PopulateListView(HWND);

// global variables
int item;
BOOL RunningOnWow64, HasPrivileges;
HMODULE hMods[MAX_MODULES];
HWND hList, hRegionsLV, ExcludeWow64CheckBox = NULL;
HMENU hMenu, hCopy2Clip;
POINT pt2;
ACCEL MyAccel;
HACCEL hAccel;
POINT pt;
HINSTANCE hGlobalInstance;
DWORD iGlobalPid = -1, pIds[MAX_PIDS];
ULONGLONG RegionAddr = -1, RegionSize = -1;

// global state variables for sorting
int PathSortOrder = 0, PidSortOrder = 0, IbSortOrder = 0, IzSortOrder = 0, ITypeSortOrder = 0;
int AddrSortOrder = 0, SizeSortOrder = 0, ProtectSortOrder = 0, StateSortOrder = 0, TypeSortOrder = 0;
