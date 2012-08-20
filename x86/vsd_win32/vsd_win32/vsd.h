/* 
$Id: vsd.h 18 2012-04-01 19:27:27Z crackinglandia $

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

#include "vsd_hdrs.h"

// function definitions
void ValidateResult(int retval)
{
	switch(retval)
	{
		case OPENPROCESS_ERROR: MessageBox(NULL, TEXT("Couldn't open process"), TEXT("Ups!"), MB_ICONERROR);break;
		case VIRTULALLOC_ERROR: MessageBox(NULL, TEXT("Coulnd't allocate memory"), TEXT("Ups!"), MB_ICONERROR);break;
		case READPROCESSMEMORY_ERROR: MessageBox(NULL, TEXT("Couldn't read memory"), TEXT("Ups!"), MB_ICONERROR);break;
		case WRITEFILE_ERROR: MessageBox(NULL, TEXT("Couldn't write file"), TEXT("Ups!"), MB_ICONERROR);break;
		case RTN_OK: MessageBox(NULL, TEXT("File successfully created!"), TEXT("Yeah!"), MB_ICONINFORMATION);break;
		case RTN_ERROR: MessageBox(NULL, TEXT("Error during operation!"), TEXT("Ups!"), MB_ICONINFORMATION);break;
		case SAVEDIALOGNOCHOICE: break;
		default: MessageBox(NULL, TEXT("Unknown error, this should never happened :("), TEXT("Ups!"), MB_ICONERROR);break;
	}
}

BOOL CALLBACK PartialDumpProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	HWND hAddrEdit, hSizeEdit;
	HANDLE hProc = INVALID_HANDLE_VALUE;
	char szText[MAX_PATH];
	int retval;

	switch(uMsg)
	{
		case WM_INITDIALOG:
			sprintf_s(szText, sizeof(szText), "[Process: %s - PID: %d]", szCaption, iGlobalPid);
			SetWindowText(hDlg, szText);

			// get the edits handles
			hAddrEdit = GetDlgItem(hDlg, DPADDRESSEDIT);
			hSizeEdit = GetDlgItem(hDlg, DPSIZEEDIT);

			// set a maximum of chars to enter
			Edit_LimitText(hAddrEdit, 8);
			Edit_LimitText(hSizeEdit, 8);

			// test if the selected process is still active
			hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, iGlobalPid);
			if(hProc != NULL)
			{
				sprintf_s(szText, sizeof(szText), "%08X", RegionAddr);
				Edit_SetText(hAddrEdit, szText);

				sprintf_s(szText, sizeof(szText), "%08X", RegionSize);
				Edit_SetText(hSizeEdit, szText);

				CloseHandle(hProc);
			}
			else
			{
				MessageBox(hDlg, TEXT("Couldn't not open process"), TEXT("Ups!"), MB_ICONERROR);
			}
			return 1;

		case WM_COMMAND:
			switch(wParam)
			{
				case DUMP_PARTIAL_REGION:
					{
						if((RegionAddr != -1) && (RegionSize != -1))
						{
							//update the values in RegionAddr and RegionSize with the values stored in
							//the editboxes
							hAddrEdit = GetDlgItem(hDlg, DPADDRESSEDIT);
							hSizeEdit = GetDlgItem(hDlg, DPSIZEEDIT);

							if(Edit_GetText(hAddrEdit, szText, 9))
							{
								if(IsValidHexString(szText))
								{
									RegionAddr = strtol(szText, NULL, 16);

									if(Edit_GetText(hSizeEdit, szText, 9))
									{
										if(IsValidHexString(szText))
										{
											RegionSize = strtol(szText, NULL, 16);

											if(DumpingModule)
											{
												retval = MyDumpModuleFunction((void*)RegionAddr, RegionSize, szGlobalModuleName, DUMPPARTIAL, FALSE, FALSE, hDlg);
											}
											else
											{
												retval = DumpMemoryRegion((void*)RegionAddr, RegionSize, DUMPPARTIAL, FALSE, FALSE, hDlg);
											}

											// test to see if there was an error
											ValidateResult(retval);
										}
										else
										{
											MessageBox(hDlg, TEXT("The value entered as Size is not a valid hex number"), TEXT("Ups!"), MB_ICONERROR);
										}
									}
									else
									{
										MessageBox(hDlg, TEXT("You didn't enter the Size"), TEXT("Are you kidding?"), MB_ICONERROR);
									}
								}
								else
								{
									MessageBox(hDlg, TEXT("The value entered as Address is not a valid hex number"), TEXT("Ups!"), MB_ICONERROR);
								}
							}
							else
							{
								MessageBox(hDlg, TEXT("You didn't enter an Address"), TEXT("Are you kidding?"), MB_ICONERROR);
							}
						}
					}
					break;

				case IDCANCEL:
					EndDialog(hDlg, 0);
			}
			break;
	}

	return 0;
}

BOOL FixHeader(HANDLE hProc, DWORD ImageBase, char* szFile)
{
	HANDLE hFile;
	unsigned int iSection;
	PIMAGE_DOS_HEADER DOSHeader;
	PIMAGE_NT_HEADERS32 NTHeaders;
	PIMAGE_SECTION_HEADER SectionHeader;
	PIMAGE_SECTION_HEADER OnFileSectionHeader;
	LPVOID RemoteSectionHeaderAddrs, ReadBuffer;
	DWORD nSections, BytesRead, FileSize;
	SIZE_T SectionHeaderSize;
	//char szText[MAX_PATH];

	// get section header data from the file on disk

	hFile = CreateFile(szFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(hFile != INVALID_HANDLE_VALUE)
	{
		FileSize = GetFileSize(hFile, NULL);
		
		ReadBuffer = VirtualAlloc(NULL, FileSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if(ReadBuffer)
		{
			if(ReadFile(hFile, ReadBuffer, FileSize, &BytesRead, NULL))
			{
				// get some data from pe header in memory
				DOSHeader = (PIMAGE_DOS_HEADER)ImageBase;
				NTHeaders = (PIMAGE_NT_HEADERS32)((ULONG)DOSHeader + DOSHeader->e_lfanew);

				nSections = NTHeaders->FileHeader.NumberOfSections;

				//sprintf_s(szText, sizeof(szText), "%08x", nSections);
				//MessageBox(NULL, szText, "Number of Sections", MB_OK);

				SectionHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)NTHeaders + NTHeaders->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER));

				// calculate the beginning of the section header in memory
				RemoteSectionHeaderAddrs = (LPVOID)((ULONG_PTR)NTHeaders + NTHeaders->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER));

				// calculate the section header size
				SectionHeaderSize = nSections * sizeof(IMAGE_SECTION_HEADER);

				DOSHeader = (PIMAGE_DOS_HEADER)ReadBuffer;
				NTHeaders = (PIMAGE_NT_HEADERS32)((ULONG)DOSHeader + DOSHeader->e_lfanew);
				OnFileSectionHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)NTHeaders + NTHeaders->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER));

				for(iSection = 0; iSection < nSections; iSection++)
				{

					SectionHeader->PointerToRawData = OnFileSectionHeader->VirtualAddress;
					SectionHeader->PointerToRelocations = OnFileSectionHeader->SizeOfRawData;

					SectionHeader->VirtualAddress = SectionHeader->PointerToRawData;
					SectionHeader->SizeOfRawData = SectionHeader->PointerToRelocations;

					//sprintf_s(szText, sizeof(szText), "%08x", SectionHeader->VirtualAddress);
					//MessageBox(NULL, szText, "Virtual Address", MB_OK);

					//sprintf_s(szText, sizeof(szText), "%08x", SectionHeader->PointerToRawData);
					//MessageBox(NULL, szText, "Pointer to Raw Data", MB_OK);

					//sprintf_s(szText, sizeof(szText), "%08x", SectionHeader->SizeOfRawData);
					//MessageBox(NULL, szText, "Size of Raw Data", MB_OK);

					//sprintf_s(szText, sizeof(szText), "%08x", SectionHeader->PointerToRelocations);
					//MessageBox(NULL, szText, "Pointer to Relocations", MB_OK);

					SectionHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)SectionHeader + sizeof(IMAGE_SECTION_HEADER));
					OnFileSectionHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)OnFileSectionHeader + sizeof(IMAGE_SECTION_HEADER));
				}

				CloseHandle(hFile);
				VirtualFree(ReadBuffer, NULL, MEM_RELEASE);
				return TRUE;

			}
			else
			{
				VirtualFree(ReadBuffer, NULL, MEM_RELEASE);
				CloseHandle(hFile);
			}

		}
		else
		{
			CloseHandle(hFile);
		}
	}

	return FALSE; 
}

DWORD GetThreadWin32StartAddress(HANDLE hThread)
{
	NTSTATUS ntStatus;
	HANDLE hCurrentProcess;
	HANDLE DupHandle;
	DWORD dwWin32StartAddress;

	if(NtQueryInformationThread == NULL) return 0;

	hCurrentProcess = GetCurrentProcess();

	if(!DuplicateHandle(hCurrentProcess, hThread, hCurrentProcess, &DupHandle, THREAD_QUERY_INFORMATION, FALSE, 0))
	{
		SetLastError(ERROR_ACCESS_DENIED);
		return 0;
	}

	ntStatus = NtQueryInformationThread(DupHandle, ThreadQuerySetWin32StartAddress, &dwWin32StartAddress, sizeof(DWORD), NULL);

	CloseHandle(DupHandle);
	CloseHandle(hCurrentProcess);

	if(!NT_SUCCESS(ntStatus)) return 0;
	
	return dwWin32StartAddress;
}

int EnumProcessThreads(HWND MyhList)
{
	//THREADENTRY32 te;
	//HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	LVITEM lvItem;
	int iCount = 0;
	unsigned int i;
	//char szText[MAX_PATH];
	NTSTATUS status;
	PSYSTEM_PROCESS_INFORMATION pInfo;
	PSYSTEM_THREAD_INFORMATION pThreads;
	LPVOID pBuffer = NULL;
	ULONG pBufferSize = 0x10000, ThreadCount;
	HANDLE hThread;

	pBuffer = (PSYSTEM_PROCESS_INFORMATION)malloc(pBufferSize);

	if(pBuffer != NULL)
	{
		while ((status = NtQuerySystemInformation(SystemProcessesAndThreadsInformation, pBuffer, pBufferSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH)
		pBuffer = (PSYSTEM_PROCESS_INFORMATION)realloc(pBuffer, pBufferSize *= 2);

		pInfo = (PSYSTEM_PROCESS_INFORMATION)pBuffer;

		// we iterate over all the entries that NtQuerySystemInformation returned.
		// if pInfo->NextEntryDelta is equal to 0, then, we finish the iterations
		for(;;)
		{
			// if the current entry belongs to our process
			if(pInfo->ProcessId == iGlobalPid)
			{
				// we take the corresponding Thread information
				ThreadCount = pInfo->ThreadCount;
				pThreads = pInfo->Threads;

				// we iterate over every single thread in the array
				for(i = 0; i < ThreadCount; i++)
				{
					memset(&lvItem, 0, sizeof(lvItem));

					lvItem.mask = LVIF_TEXT | LVIF_PARAM;
					lvItem.cchTextMax = MAX_PATH;
					lvItem.iItem = lvItem.lParam = i;
					lvItem.iSubItem = 0;

					if(ListView_InsertItem(MyhList, &lvItem) != -1)
					{
						//sprintf_s(szText, sizeof(szText), "%08X", pThreads[i].ClientId.UniqueThread);
						//ListView_SetItemText(MyhList, i, THREAD_ID_COL, szText);
						ListView_SetItemText(MyhList, i, THREAD_ID_COL, (LPSTR)DwordToHex(pThreads[i].ClientId.UniqueThread));

						//sprintf_s(szText, sizeof(szText), "%08X", pThreads[i].BasePriority);
						//ListView_SetItemText(MyhList, i, THREAD_PRIORITY_COL, szText);
						ListView_SetItemText(MyhList, i, THREAD_PRIORITY_COL, (LPSTR)DwordToHex(pThreads[i].BasePriority));
						
						//sprintf_s(szText, sizeof(szText), "%08x", pThreads[i].StartAddress);
						//ListView_SetItemText(MyhList, i, THREAD_STARTADDRESS_COL, szText);
												
						ListView_SetItemText(MyhList, i, THREAD_STATE_COL, (LPSTR)GetWaitReasonString(pThreads[i].WaitReason));

						ListView_SetItemText(MyhList, i, THREAD_TEB_COL, (LPSTR)DwordToHex((DWORD)GetThreadTebAddress(pThreads[i].ClientId.UniqueThread)));

						hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, pThreads[i].ClientId.UniqueThread);
						if(hThread != NULL)
						{
							ListView_SetItemText(MyhList, i, THREAD_STARTADDRESS_COL, (LPSTR)DwordToHex((DWORD)GetThreadWin32StartAddress(hThread)));
							CloseHandle(hThread);
						}
					}
					else
					{
						MessageBox(NULL, TEXT("Couldn't insert item!"), TEXT("Ups!"), MB_ICONERROR);
					}
				}
			}

			if(pInfo->NextEntryDelta == 0)
				break;

			pInfo = (PSYSTEM_PROCESS_INFORMATION)(((PUCHAR)pInfo) + pInfo->NextEntryDelta);

		}//while(pInfo->NextEntryDelta != 0);
		
		free(pBuffer);
	}
	//if(hSnap != INVALID_HANDLE_VALUE)
	//{
	//	te.dwSize = sizeof(te);
	//	if(Thread32First(hSnap, &te))
	//	{
	//		do
	//		{
	//			if(te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(te.th32OwnerProcessID))
	//			{
	//				if(te.th32OwnerProcessID  == iGlobalPid)
	//				{
	//					memset(&lvItem, 0, sizeof(lvItem));

	//					lvItem.mask = LVIF_TEXT | LVIF_PARAM;
	//					lvItem.cchTextMax = MAX_PATH;
	//					lvItem.iItem = lvItem.lParam = iCount;
	//					lvItem.iSubItem = 0;

	//					if(ListView_InsertItem(MyhList, &lvItem) != -1)
	//					{
	//						sprintf_s(szText, sizeof(szText), "%08X", te.th32ThreadID);
	//						ListView_SetItemText(MyhList, iCount, THREAD_ID_COL, szText);

	//						sprintf_s(szText, sizeof(szText), "%08X", te.tpBasePri);
	//						ListView_SetItemText(MyhList, iCount, THREAD_PRIORITY_COL, szText);
	//					}
	//					else
	//					{
	//						MessageBox(NULL, TEXT("Couldn't insert item!"), TEXT("Ups!"), MB_ICONERROR);
	//					}
	//					
	//					iCount++;
	//				}
	//			}
	//			
	//			te.dwSize = sizeof(te);
	//		}
	//		while(Thread32Next(hSnap, &te));
	//	}

	//	CloseHandle(hSnap);
	//}

	return RTN_OK;
}

const char* GetWaitReasonString(unsigned long WaitReason)
{
	switch(WaitReason)
	{
		case Executive: return "Wait: Executive";
		case FreePage: return "Wait: FreePage";
		case PageIn: return "Wait: PageIn";
		case PoolAllocation: return "Wait: PoolAllocation";
		case DelayExecution: return "Wait: DelayExecution";
		case Suspended: return "Wait: Suspended";
		case UserRequest: return "Wait: UserRequest";
		case WrExecutive: return "Wait: WrExecutive";
		case WrFreePage: return "Wait: WrFreePage";
		case WrPageIn: return "Wait: WrPageIn";
		case WrPoolAllocation: return "Wait: WrPoolAllocation";
		case WrDelayExecution: return "Wait: WrDelayExecution";
		case WrSuspended: return "Wait: WrSuspended";
		case WrUserRequest: return "Wait: WrUserRequest";
		case WrEventPair: return "Wait: WrEventPair";
		case WrQueue: return "Wait: WrQueue";
		case WrLpcReceive: return "Wait: WrLpcReceive";
		case WrLpcReply: return "Wait: WrLpcReply";
		case WrVirtualMemory: return "Wait: WrVirtualMemory";
		case WrPageOut: return "Wait: WrPageOut";
		case WrRendezvous: return "Wait: WrRendezvous";
		case Spare2: return "Wait: Spare2";
		case Spare3: return "Wait: Spare3";
		case Spare4: return "Wait: Spare4";
		case Spare5: return "Wait: Spare5";
		case WrCalloutStack: return "Wait: WrCalloutStack";
		case WrKernel: return "Wait: WrKernel";
		case WrResource: return "Wait: WrResource";
		case WrPushLock: return "Wait: WrPushLock";
		case WrMutex: return "Wait: WrMutex";
		case WrQuantumEnd: return "Wait: WrQuantumEnd";
		case WrDispatchInt: return "Wait: WrDispatchInt";
		case WrPreempted: return "Wait: WrPreempted";
		case WrYieldExecution: return "Wait: WrYieldExecution";
		case WrFastMutex: return "Wait: WrFastMutex";
		case WrGuardedMutex: return "Wait: WrGuardedMutex";
		case WrRundown: return "Wait: WrRundown";
		case MaximumWaitReason: return "Wait: MaximumWaitReason";
		default: return "Wait: Unknown";
	}
}

void CreateColumnsThreadsLV(HWND MyhList)
{
	int index;
	LVCOLUMN lvCol = {0};
	char* lvColTitles[] = {"Thread ID", "Priority", "TEB Address", "Start Address", "State"};
	char szFmtText[MAX_PATH];

	for(index = 0; index < 5; index++)
	{
		lvCol.mask = LVCF_TEXT | LVCF_SUBITEM | LVCF_WIDTH | LVCF_IDEALWIDTH;
		lvCol.pszText = lvColTitles[index];
		
		lvCol.cx = lvCol.cxIdeal = 101;

		lvCol.cchTextMax = strlen(lvColTitles[index]);

		if(ListView_InsertColumn(MyhList, index, &lvCol) == -1)
		{
			sprintf_s(szFmtText, sizeof(szFmtText), "Couldn't insert column %d", index);
			MessageBox(MyGetWindowOwner(MyhList), szFmtText, TEXT("Ups!"), MB_ICONERROR);
		}
	}
}

HWND PopulateThreadsLV(HWND hDlg)
{
	HWND hMyList;

	hMyList = GetDlgItem(hDlg, THREADSLV);

	if(hMyList)
	{
		/*
			ComCtl32.dll version 6 has problems with LVS_EX_GRIDLINES when its scrolled vertically.
			An option to avoid this issue is to disable the LVS_EX_GRIDLINES style.
			Another option is to disable the Windows XP Style.

			* http://stackoverflow.com/questions/1416793/listview-gridlines-issue
			* http://www.ureader.com/msg/1484143.aspx
		*/
		ListView_SetExtendedListViewStyle(hMyList, LVS_EX_GRIDLINES | LVS_EX_FULLROWSELECT | LVS_SORTASCENDING);
		
		CreateColumnsThreadsLV(hMyList);
		EnumProcessThreads(hMyList);
	}

	return hMyList;
}

void MyResumeThread(HWND MyhList, int iPos)
{
	HANDLE hThread;
	DWORD tid;
	char szTid[9];

	ListView_GetItemText(MyhList, iPos, THREAD_ID_COL, szTid, sizeof(szTid));
						
	tid = strtol(szTid, 0, 16);

	hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
	if(hThread)
	{
		if(ResumeThread(hThread) == -1)
		{
			MessageBox(NULL, TEXT("Couldn't resume thread"), TEXT("Ups!"), MB_ICONERROR);
		}
		CloseHandle(hThread);
	}
}

void MySuspendThread(HWND MyhList, int iPos)
{
	HANDLE hThread;
	DWORD tid;
	char szTid[9];

	ListView_GetItemText(MyhList, iPos, THREAD_ID_COL, szTid, sizeof(szTid));
						
	tid = strtol(szTid, 0, 16);

	hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
	// before we suspend the thread, we must be sure that the thread is not
	// already suspended, so, we first ask for its suspended count. If this value is
	// greater than 0, then, the thread is suspended.
	if(GetSuspendThreadCount(hThread) > 0)
	{
		MessageBox(NULL, TEXT("Thread is already suspended!"), TEXT("Be careful!"), MB_ICONINFORMATION);
	}
	else
	{
		if(hThread)
		{
			if(SuspendThread(hThread) == -1)
			{
				MessageBox(NULL, TEXT("Couldn't suspend thread"), TEXT("Ups!"), MB_ICONERROR);
			}
			CloseHandle(hThread);
		}
	}
}

void MyTerminateThread(HWND MyhList, int iPos)
{
	HANDLE hThread;
	DWORD tid, ExitCode;
	char szTid[9];

	ListView_GetItemText(MyhList, iPos, THREAD_ID_COL, szTid, sizeof(szTid));
						
	tid = strtol(szTid, 0, 16);

	hThread = OpenThread(THREAD_TERMINATE, FALSE, tid);
	if(hThread)
	{
		GetExitCodeThread(hThread, &ExitCode);
		if(TerminateThread(hThread, ExitCode) == 0)
		{
			MessageBox(NULL, TEXT("Couldn't terminate thread"), TEXT("Ups!"), MB_ICONERROR);
		}
		CloseHandle(hThread);
	}
}

BOOL CALLBACK Filter(HWND hWin, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch(uMsg)
	{
		// we are interested in the WM_CHAR message
		case WM_CHAR:
			if((wParam >= 0x30 && wParam <= 0x39) || (wParam >= 'a' && wParam <= 'f') || (wParam >= 'A' && wParam <= 'F') || LOBYTE(wParam) == VK_BACK)
			{
				if(wParam >= 'a' && wParam <= 'f')
					wParam = wParam - 0x20;
				return CallWindowProc((WNDPROC)wndproc, hWin, uMsg, wParam, lParam);
			}
			break;

		default:
			// here, we dispatch the rest of the messages
			return CallWindowProc((WNDPROC)wndproc, hWin, uMsg, wParam, lParam);
	}

	// return the original uMsg parameter received from the calling procedure
	return uMsg;
}

BOOL CALLBACK PatchProcessDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	char szText[MAX_PATH];
	DWORD AddrsToPatch, BytesRead, OldProtect, BytesWritten;
	int NroBytesToPatch, retval;
	static int aux_NroBytesToPatch;
	HANDLE hProc;
	int* m_buffer, *hexOriginalBytes, *binBytes;

	switch(uMsg)
	{
		case WM_INITDIALOG:
			SetClassLongPtr(hDlg, GCLP_HICON, (long)LoadIcon(0, IDI_INFORMATION));

			sprintf_s(szText, sizeof(szText), "Patch process - [Process: %s - PID: %d]", szCaption, iGlobalPid);
			SetWindowText(hDlg, szText);

			// set the text limit in the edit holding the address to patch
			hAddrToPatch = GetDlgItem(hDlg, EDT_ADDRESS2PATCH);
			if(hAddrToPatch)
			{
				// limit the text size the user can fill in the edit
				Edit_LimitText(hAddrToPatch, 8);

				// retrive the current windows procedure handle
				wndproc = GetWindowLong(hAddrToPatch, GWL_WNDPROC);
				// set a hook to a new windows procedure (callback) for this control
				SetWindowLong(hAddrToPatch, GWL_WNDPROC, (LONG)&Filter);
			}

			hNewBytes = GetDlgItem(hDlg, EDT_NEWBYTES);
			if(hNewBytes)
			{
				// here, we set a new window procedure for this edit control
				SetWindowLong(hNewBytes, GWL_WNDPROC, (LONG)&Filter);
			}

			// handle of the control holding the number of bytes to patch
			hNroBytesToPatch = GetDlgItem(hDlg, NRO_BYTES2PATCH);

			// handle of the control holding the original bytes
			hOriginalBytes = GetDlgItem(hDlg, EDT_ORIGINALBYTES);

			// set the range for the spin control
			SendDlgItemMessage(hDlg, SPIN_NRO_BYTES, UDM_SETRANGE, 0, MAKESPINRANGE(MIN_SPIN_POS, MAX_SPIN_POS));

			// set the initial value for the spin control
			SendDlgItemMessage(hDlg, SPIN_NRO_BYTES, UDM_SETPOS, 0, 1);
			return 1;

		case WM_COMMAND:
			switch(LOWORD(wParam))
			{
				case IDOK:
					// get the number of bytes to patch
					Edit_GetText(hNroBytesToPatch, szText, sizeof(szText));
					NroBytesToPatch = atoi(szText);
					/* 
						aux_NroBytesToPatch is declared as static because we lose the real value
						after the HexToBin() call. Fucking inline ASM!.
					*/
					aux_NroBytesToPatch = NroBytesToPatch;

					// get the address to patch
					Edit_GetText(hAddrToPatch, szText, sizeof(szText));
					AddrsToPatch = strtol(szText, 0, 16);

					// alloc memory for new bytes
					m_buffer = (int*)malloc(NroBytesToPatch * 3);
					if(m_buffer == NULL)
					{
						MessageBox(NULL, TEXT("malloc failed!"), TEXT("Ups!"), MB_ICONERROR);
						return 0;
					}
					// converts the lowercase chars to uppercase
					retval = Edit_GetText(hNewBytes, (LPSTR)m_buffer, NroBytesToPatch * 3);
					retval = CharUpperBuff((LPSTR)m_buffer, retval);

					binBytes = (int*)malloc(retval);
					if(binBytes == NULL)
					{
						MessageBox(NULL, TEXT("malloc failed!"), TEXT("Ups!"), MB_ICONERROR);
						return 0;
					}

					if(HexToBin((char*)m_buffer, retval, NroBytesToPatch, (char*)binBytes))
					{
						hProc = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, iGlobalPid);
						if(hProc != NULL)
						{
							if(VirtualProtectEx(hProc, (LPVOID)AddrsToPatch, aux_NroBytesToPatch, PAGE_READWRITE, &OldProtect))
							{
								if(WriteProcessMemory(hProc, (LPVOID)AddrsToPatch, binBytes, aux_NroBytesToPatch, &BytesWritten))
								{
									Edit_SetText(hOriginalBytes, (LPCSTR)m_buffer);
								}
								else
								{
									MessageBox(NULL, TEXT("Error writing in process!"), TEXT("Ups!"), MB_ICONERROR);
								}
							}
							else
							{
								MessageBox(NULL, TEXT("VirtualProtectEx error!"), TEXT("Ups!"), MB_ICONERROR);
							}
							CloseHandle(hProc);
						}
						else
						{
							MessageBox(hDlg, TEXT("Error opening process!"), TEXT("Ups!"), MB_ICONERROR);
						}
					}
					
					free(m_buffer);
					free(binBytes);
					break;

				case BT_SEARCH_BYTES:
					// read how many bytes the user wants to read
					Edit_GetText(hNroBytesToPatch, szText, sizeof(szText));
					NroBytesToPatch = atoi(szText);
					
					if(NroBytesToPatch == 0)
						break;

					// get the address from the edit box
					Edit_GetText(hAddrToPatch, szText, sizeof(szText));

					if(strlen(szText) == 0)
					{
						MessageBox(hDlg, TEXT("Address edit box is empty!"), TEXT("c'mon!!"), MB_ICONERROR);
						break;
					}

					// check if the string is a valid hex string
					if(IsValidHexString(szText))
					{
						// open the process we want to read memory from
						hProc = OpenProcess(PROCESS_VM_READ, FALSE, iGlobalPid);
						if(hProc != NULL)
						{
							// allocate memory to hold the data
							m_buffer = (int*)malloc(NroBytesToPatch);
							if(m_buffer)
							{
								// convert the hex string to a number
								AddrsToPatch = strtol(szText, 0, 16);
								// read the bytes from memory
								if(ReadProcessMemory(hProc, (LPCVOID)AddrsToPatch, m_buffer, NroBytesToPatch, &BytesRead))
								{
									hexOriginalBytes = (int*)malloc((BytesRead*3)+1);

									BinToHex((char*)m_buffer, BytesRead, (char*)hexOriginalBytes);
									SetDlgItemText(hDlg, EDT_ORIGINALBYTES, (LPCSTR)hexOriginalBytes);

									free(m_buffer);
									free(hexOriginalBytes);
									CloseHandle(hProc);
								}
								else
								{
									CloseHandle(hProc);
									free(m_buffer);
									MessageBox(hDlg, TEXT("Error reading memory!"), TEXT("Ups!"), MB_ICONERROR);
								}
							}
							else
							{
								CloseHandle(hProc);
								MessageBox(hDlg, TEXT("Error allocating memory!"), TEXT("Ups!"), MB_ICONERROR);
							}
						}
						else
						{
							MessageBox(hDlg, TEXT("Error opening process!"), TEXT("Ups!"), MB_ICONERROR);
						}
					}
					else
					{
						MessageBox(hDlg, TEXT("Address must be a valid hex number!"), TEXT("Ups!"), MB_ICONERROR);
					}
					break;

				case IDCANCEL:
					EndDialog(hDlg, 0);
			}
	}
	return 0;
}

bool HexToBin(char* hexdata, unsigned long nHexData, unsigned long nroBytesToWrite, char* binoutput)
{
	/*
		This function receives a pointer to a memory buffer containing an hex string
		and converts it to its binary representation

		The output is like this: 000203040506
	*/
	char msgText[] = TEXT("Wrong bytes dude!");
	char msgTitle[] = TEXT("Wrong!!!");

	int* bin_aux_buffer;
	
	bool retval = TRUE;

	bin_aux_buffer = (int*)malloc(nHexData * 3);
	if(bin_aux_buffer)
	{
		memset(bin_aux_buffer, 0, nHexData * 3);

		__asm
		{
			mov ecx, dword ptr ds:[nHexData]
			mov esi, dword ptr ds:[hexdata]
			mov edi, dword ptr ds:[bin_aux_buffer]
			xor eax, eax
			cld
	
		convert:
				lods byte ptr ds:[esi]
				cmp al, ' '
				je _continue
				sub al, 0x30
				js _error
				cmp al, 0x16
				ja _error
				cmp al, 0x0a
				jb _include_byte
				sub al, 0x07
				cmp al, 0x0a
				jb _error

		_include_byte:
				stos byte ptr es:[edi]
		_continue:
				loop convert
				sub edi, dword ptr ds:[bin_aux_buffer]
				shr edi, 1
				cmp edi, dword ptr ds:[nroBytesToWrite]
				jne _error
				mov ecx, edi
				mov edi, dword ptr ds:[bin_aux_buffer]
				mov esi, edi
		aad_loop:
				lods word ptr ds:[esi]
				xchg ah, al
				// AAD -> AL = AL + AH * 16
				_emit 0xd5
				_emit 0x10
				stos byte ptr es:[edi]
				loop aad_loop
				jmp ThanksAllFolks
		_error:
				push MB_ICONERROR
				lea eax, msgTitle
				push eax
				lea eax, msgText
				push eax
				push NULL
				call dword ptr ds:[MessageBox]
				mov retval, 0
				jmp fin
		ThanksAllFolks:
				mov eax, nHexData
				push eax
				mov eax, bin_aux_buffer
				push eax
				mov eax, nHexData
				push eax
				mov eax, binoutput
				push eax
				call [memcpy_s]
				mov eax, bin_aux_buffer
				push eax
				call [free]
		fin:
		}
		return retval;
	}
	return FALSE;
}

void BinToHex(char* bindata, unsigned long nroBytes, char* hexoutput)
{
	/* 
		This function receives a pointer to a memory buffer containing binary data
		and converts it to its hex representation.

		This is how Pupe2002 do it, i know, it is not the best way to do it but, hey, it works quite well.

		The output is like this: 00 01 02 03 04 05 06 ...
	*/

	int* hex_aux_buffer;
	char outputfmt[] = "%.2lX ";

	hex_aux_buffer = (int*)malloc((nroBytes*3)+1);
	if(hex_aux_buffer)
	{
		memset(hex_aux_buffer, 0, (nroBytes*3)+1);

		__asm
		{
			mov ecx, dword ptr ds:[nroBytes]
			mov esi, dword ptr ds:[bindata]
			mov edi, dword ptr ds:[hex_aux_buffer]
			xor eax, eax
			dale_toda:
				lods byte ptr ds:[esi]
				push ecx
				push eax
				lea edx, outputfmt
				push edx
				push edi
				call dword ptr ds:[wsprintfA]
				add esp, 0x0c
				add edi, 3
				pop ecx
			loop dale_toda
		}

		memcpy_s(hexoutput, (nroBytes * 3)+1, hex_aux_buffer, (nroBytes * 3)+1);
		free(hex_aux_buffer);
	}
}

void SortThreadsListView(HWND MyhList, int iSubItem)
{
	switch(iSubItem)
	{
		case THREAD_ID_COL:
			if ((ThreadIdSortOrder == NO_SORT) || (ThreadIdSortOrder == THREAD_ID_SORT_DESCENDING))
			{
				ListView_SortItems(MyhList, ThreadsCompareProc, THREAD_ID_SORT_ASCENDING);
				UpdatelParam(MyhList);
				ThreadIdSortOrder = THREAD_ID_SORT_ASCENDING;
			}
			else
			{
				ListView_SortItems(MyhList, ThreadsCompareProc, THREAD_ID_SORT_DESCENDING);
				UpdatelParam(MyhList);
				ThreadIdSortOrder = THREAD_ID_SORT_DESCENDING;
			}
			break;

		case THREAD_PRIORITY_COL:
			if ((ThreadPrioritySortOrder == NO_SORT) || (ThreadPrioritySortOrder == THREAD_PRIORITY_SORT_DESCENDING))
			{
				ListView_SortItems(MyhList, ThreadsCompareProc, THREAD_PRIORITY_SORT_ASCENDING);
				UpdatelParam(MyhList);
				ThreadPrioritySortOrder = THREAD_PRIORITY_SORT_ASCENDING;
			}
			else
			{
				ListView_SortItems(MyhList, ThreadsCompareProc, THREAD_PRIORITY_SORT_DESCENDING);
				UpdatelParam(MyhList);
				ThreadPrioritySortOrder = THREAD_PRIORITY_SORT_DESCENDING;
			}
			break;

		case THREAD_TEB_COL:
			if ((ThreadTebSortOrder == NO_SORT) || (ThreadTebSortOrder == THREAD_TEB_SORT_DESCENDING))
			{
				ListView_SortItems(MyhList, ThreadsCompareProc, THREAD_TEB_SORT_ASCENDING);
				UpdatelParam(MyhList);
				ThreadTebSortOrder = THREAD_TEB_SORT_ASCENDING;
			}
			else
			{
				ListView_SortItems(MyhList, ThreadsCompareProc, THREAD_TEB_SORT_DESCENDING);
				UpdatelParam(MyhList);
				ThreadTebSortOrder = THREAD_TEB_SORT_DESCENDING;
			}
			break;

		case THREAD_STARTADDRESS_COL:
			if ((ThreadStartSortOrder == NO_SORT) || (ThreadStartSortOrder == THREAD_START_SORT_DESCENDING))
			{
				ListView_SortItems(MyhList, ThreadsCompareProc, THREAD_START_SORT_ASCENDING);
				UpdatelParam(MyhList);
				ThreadStartSortOrder = THREAD_START_SORT_ASCENDING;
			}
			else
			{
				ListView_SortItems(MyhList, ThreadsCompareProc, THREAD_START_SORT_DESCENDING);
				UpdatelParam(MyhList);
				ThreadStartSortOrder = THREAD_START_SORT_DESCENDING;
			}
			break;

		case THREAD_STATE_COL:
			if ((ThreadStateSortOrder == NO_SORT) || (ThreadStateSortOrder == THREAD_STATE_SORT_DESCENDING))
			{
				ListView_SortItems(MyhList, ThreadsCompareProc, THREAD_STATE_SORT_ASCENDING);
				UpdatelParam(MyhList);
				ThreadStateSortOrder = THREAD_STATE_SORT_ASCENDING;
			}
			else
			{
				ListView_SortItems(MyhList, ThreadsCompareProc, THREAD_STATE_SORT_DESCENDING);
				UpdatelParam(MyhList);
				ThreadStateSortOrder = THREAD_STATE_SORT_DESCENDING;
			}
			break;
	}
}

BOOL CALLBACK ThreadsDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	int SelItem;
	char szText[MAX_PATH];

	switch(uMsg)
	{
		case WM_INITDIALOG:
			SetClassLongPtr(hDlg, GCLP_HICON, (long)LoadIcon(0, IDI_INFORMATION));

			sprintf_s(szText, sizeof(szText), "Threads - [Process: %s - PID: %d]", szCaption, iGlobalPid);
			SetWindowText(hDlg, szText);

			hThreadMenu = CreatePopupMenu();
			AppendMenu(hThreadMenu, MF_STRING, IDM_RESUME_THREAD, TEXT("&Resume"));
			AppendMenu(hThreadMenu, MF_STRING, IDM_SUSPEND_THREAD, TEXT("&Suspend"));
			AppendMenu(hThreadMenu, MF_STRING, IDM_TERMINATE_THREAD, TEXT("&Terminate"));
			
			InsertMenu(hThreadMenu, 2, MF_SEPARATOR, 0, "-");

			AppendMenu(hThreadMenu, MF_STRING, IDM_SELECTALL, TEXT("Select &All"));
			AppendMenu(hThreadMenu, MF_STRING, IDM_COPY2CLIPBOARD, TEXT("&Copy to Clipboard"));
			
			InsertMenu(hThreadMenu, 2, MF_SEPARATOR, 0, "-");
			
			AppendMenu(hThreadMenu, MF_STRING, IDM_REFRESH_THREAD_LIST, TEXT("R&efresh"));

			hThreadsLV = PopulateThreadsLV(hDlg);
			return 1;

		case WM_NOTIFY:
			switch(LOWORD(wParam))
			{
				case THREADSLV:
					switch(((LPNMHDR)lParam)->code)
					{
						case LVN_COLUMNCLICK:
							{
								NMLISTVIEW* pListView = (NMLISTVIEW*)lParam;
								SortThreadsListView(hThreadsLV, pListView->iSubItem);
							}
							break;
						default: break;
					}
				default: break;
			}
			return 0;

		case WM_CONTEXTMENU:
			GetCursorPos(&pt2);
			SelItem = TrackPopupMenuEx(hThreadMenu, TPM_RETURNCMD, pt2.x, pt2.y, hDlg, NULL);

			switch(SelItem)
			{
				case IDM_SELECTALL:
					SelectAllItems(hThreadsLV);
					break;

				case IDM_COPY2CLIPBOARD:
					CopyDataToClipBoard(hThreadsLV, 5);
					break;

				case IDM_RESUME_THREAD:
					DoAction(hThreadsLV, RESUME_THREAD_ACTION);
					RefreshThreadsLV(hThreadsLV);
					break;

				case IDM_SUSPEND_THREAD:
					DoAction(hThreadsLV, SUSPEND_THREAD_ACTION);
					RefreshThreadsLV(hThreadsLV);
					break;

				case IDM_TERMINATE_THREAD:
					DoAction(hThreadsLV, TERMINATE_THREAD_ACTION);
					RefreshThreadsLV(hThreadsLV);
					break;

				case IDM_REFRESH_THREAD_LIST:					
					RefreshThreadsLV(hThreadsLV);
					break;

				default: break;
			}
			break;

		case WM_COMMAND:
			switch(wParam)
			{
				case BT_REFRESH_THREADSLV:
					RefreshThreadsLV(hThreadsLV);
					break;

				case BT_RESUME_THREAD:
					DoAction(hThreadsLV, RESUME_THREAD_ACTION);
					RefreshThreadsLV(hThreadsLV);
					break;

				case BT_TERMINATE_THREAD:
					DoAction(hThreadsLV, TERMINATE_THREAD_ACTION);
					RefreshThreadsLV(hThreadsLV);
					break;

				case BT_SUSPEND_THREAD:
					DoAction(hThreadsLV, SUSPEND_THREAD_ACTION);
					RefreshThreadsLV(hThreadsLV);
					break;

				case IDOK:
				case IDCANCEL:
					EndDialog(hDlg, 0);
			}
	}

	return 0;
}

void DoAction(HWND MyhList, int Action)
{
	int itemPos, iCount;

	iCount = ListView_GetItemCount(MyhList);

	itemPos = 0;
	while(iCount > 0)
	{
		if(ListView_GetItemState(MyhList, itemPos, LVIS_SELECTED) == LVIS_SELECTED)
		{
			switch(Action)
			{
				case SUSPEND_THREAD_ACTION:
					MySuspendThread(MyhList, itemPos);
					break;
				
				case TERMINATE_THREAD_ACTION:
					MyTerminateThread(MyhList, itemPos);
					break;

				case RESUME_THREAD_ACTION:
					MyResumeThread(MyhList, itemPos);		
					break;

				default: break;
			}
		}

		itemPos ++;
		iCount--;
	}
}

void RefreshThreadsLV(HWND MyhList)
{
	ListView_DeleteAllItems(MyhList);
	EnumProcessThreads(MyhList);
}

BOOL PastePEHeader(HANDLE hProc, DWORD ImageBase, char* szFile)
{
	HANDLE hFile;
	DWORD FileSize, BytesRead, BytesWritten, PE32HeaderSize, OldProtect;
	PIMAGE_DOS_HEADER DOSHeader;
	PIMAGE_NT_HEADERS32 PEHeader32;
	LPVOID ReadBuffer, ReadBuffer2;

	// open the file we want to get the PEHeader from
	hFile = CreateFile(szFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(hFile != INVALID_HANDLE_VALUE)
	{
		// get its file size
		FileSize = GetFileSize(hFile, NULL);

		// allocate a buffer to store the file data
		ReadBuffer = VirtualAlloc(NULL, FileSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if(ReadBuffer)
		{
			// read the file content
			if(ReadFile(hFile, ReadBuffer, FileSize, &BytesRead, NULL))
			{
				// calculate the start of the PEHeader structure
				DOSHeader = (PIMAGE_DOS_HEADER)ReadBuffer;
				PEHeader32 = (PIMAGE_NT_HEADERS32)((ULONG)DOSHeader + DOSHeader->e_lfanew);
				// calculate the PEHeader size
				PE32HeaderSize = DOSHeader->e_lfanew + sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS32);

				// frees the allocated buffer
				//VirtualFree(ReadBuffer, 0, MEM_RELEASE);

				// set the file pointer to the beginning of the file
				SetFilePointer(hFile, DOSHeader->e_lfanew, NULL, FILE_BEGIN);

				// allocate a new buffer to hold the original PEHeader data
				ReadBuffer2 = VirtualAlloc(NULL, PE32HeaderSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

				if(ReadBuffer2)
				{
					// read just the PEHeader data from the original file
					if(ReadFile(hFile, ReadBuffer2, PE32HeaderSize, &BytesRead, NULL))
					{
						// change the page permissions to the memory where the original
						// PEHeader will be written
						if(VirtualProtectEx(hProc, (LPVOID)ImageBase, PE32HeaderSize, PAGE_READWRITE, &OldProtect))
						{
							// write the original PEHeader data to the process' PEHeader
							if(WriteProcessMemory(hProc, (LPVOID)((ULONG_PTR)ImageBase + DOSHeader->e_lfanew), ReadBuffer2, PE32HeaderSize, &BytesWritten))
							{
								// restore old permissions
								VirtualProtectEx(hProc, (LPVOID)ImageBase, PE32HeaderSize, OldProtect, &OldProtect);

								// release handles and allocated memory
								VirtualFree(ReadBuffer, 0, MEM_RELEASE);
								VirtualFree(ReadBuffer2, 0, MEM_RELEASE);
								CloseHandle(hFile);
								return TRUE;
							}
							else
							{
								VirtualFree(ReadBuffer, 0, MEM_RELEASE);
								VirtualFree(ReadBuffer2, 0, MEM_RELEASE);
								CloseHandle(hFile);
							}
						}
						else
						{
							VirtualFree(ReadBuffer, 0, MEM_RELEASE);
							VirtualFree(ReadBuffer2, 0, MEM_RELEASE);
							CloseHandle(hFile);
						}
					}
					else
					{
						VirtualFree(ReadBuffer, 0, MEM_RELEASE);
						VirtualFree(ReadBuffer2, 0, MEM_RELEASE);
						CloseHandle(hFile);
					}
				}
				else
				{
					VirtualFree(ReadBuffer, 0, MEM_RELEASE);
					VirtualFree(ReadBuffer2, 0, MEM_RELEASE);
					CloseHandle(hFile);
				}
			}
			else
			{
				VirtualFree(ReadBuffer, 0, MEM_RELEASE);
				VirtualFree(ReadBuffer2, 0, MEM_RELEASE);
				CloseHandle(hFile);
			}
		}
		else
		{
			CloseHandle(hProc);
		}
	}

	return FALSE;
}

int MyDumpModuleFunction(void* addr, DWORD size, char* szModuleName, int DumpType, BOOL PasteHeaderFromDisk, BOOL bFixHeader, HWND hwndOwner)
{
	HANDLE hProc, hFile;
	DWORD BytesRead, BytesWritten, offset = 0, ActualSize = 0x1000;
	LPVOID BaseAddress, AuxBuffer;
	OPENFILENAME ofn;
	char szFile[MAX_PATH]; //szProcName[MAX_PATH];

	BaseAddress = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	AuxBuffer = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if(BaseAddress && AuxBuffer)
	{
		hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, iGlobalPid);
		if(hProc != NULL)
		{
			if(DumpType == DUMPPARTIAL)
			{
				if(ReadProcessMemory(hProc, (LPVOID)addr, BaseAddress, size, &BytesRead) == 0)
				{
					VirtualFree(BaseAddress, 0, MEM_RELEASE);
					VirtualFree((LPVOID)AuxBuffer, 0, MEM_RELEASE);
					CloseHandle(hProc);
					return READPROCESSMEMORY_ERROR;
				}
			}
			else
			{
				while(ActualSize <= size)
				{
					if(ReadProcessMemory(hProc, (LPVOID)((DWORD)addr+offset), AuxBuffer, 0x1000, &BytesRead) == 0)
					{
						VirtualFree(BaseAddress, 0, MEM_RELEASE);
						VirtualFree((LPVOID)AuxBuffer, 0, MEM_RELEASE);
						CloseHandle(hProc);
						return READPROCESSMEMORY_ERROR;
					}
					memcpy_s((LPVOID)((DWORD)BaseAddress+offset), size, AuxBuffer, 0x1000);
					ActualSize += 0x1000;
					offset += 0x1000;
				}
			}

			memset(&ofn, 0, sizeof(ofn));

			ofn.lStructSize = sizeof(OPENFILENAME);
			ofn.hwndOwner = hwndOwner;

			if(DumpType == DUMPREGION || DumpType == DUMPPARTIAL)
			{
				ofn.lpstrFilter = TEXT("Dump File *.DMP");
				ofn.lpstrTitle = TEXT("Save memory dump ...");

				sprintf_s(szFile,  sizeof(szFile), "addr=%08X-size=%08X.dmp", (DWORD)addr, (DWORD)size);
				ofn.lpstrFile = szFile;
			}
			else
			{
				ofn.lpstrFilter = TEXT("Executable file (*.exe)\0*.exe\0Dll file (*.dll)\0*.dll\0");
				ofn.lpstrTitle = TEXT("Save full dump ...");

				sprintf_s(szFile, sizeof(szFile), "%s", szModuleName);
				ofn.lpstrFile = szFile;
			}

			ofn.nMaxFile = sizeof(szFile)/sizeof(*szFile);
			ofn.lpstrFileTitle = NULL;
			ofn.lpstrInitialDir = (LPSTR)NULL;
			ofn.Flags = OFN_SHOWHELP | OFN_OVERWRITEPROMPT;
				
			if(GetSaveFileName(&ofn))
			{
				hFile = CreateFile(ofn.lpstrFile, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
				if(hFile != NULL)
				{
					if(PasteHeaderFromDisk)
						PastePEHeader(hProc, (DWORD)BaseAddress, szModuleName);

					if(bFixHeader)
						FixHeader(hProc, (DWORD)BaseAddress, szModuleName);

					if(!WriteFile(hFile, BaseAddress, size, &BytesWritten, NULL))
					{
						VirtualFree(BaseAddress, 0, MEM_RELEASE);
						VirtualFree((LPVOID)AuxBuffer, 0, MEM_RELEASE);
						CloseHandle(hProc);
						CloseHandle(hFile);
						return WRITEFILE_ERROR;
					}
					else
					{
						CloseHandle(hFile);
						VirtualFree((LPVOID)AuxBuffer, 0, MEM_RELEASE);
						VirtualFree(BaseAddress, 0, MEM_RELEASE);
						CloseHandle(hProc);

						return RTN_OK;
					}
				}
				else
				{
					VirtualFree((LPVOID)BaseAddress, 0, MEM_RELEASE);
					VirtualFree((LPVOID)AuxBuffer, 0, MEM_RELEASE);
					CloseHandle(hProc);
					return CREATEFILE_ERROR;
				}
			}
			else
			{
				VirtualFree((LPVOID)BaseAddress, 0, MEM_RELEASE);
				VirtualFree((LPVOID)AuxBuffer, 0, MEM_RELEASE);
				CloseHandle(hProc);
				return SAVEDIALOGNOCHOICE;
			}
		}
		else
		{	
			VirtualFree((LPVOID)BaseAddress, 0, MEM_RELEASE);
			VirtualFree((LPVOID)AuxBuffer, 0, MEM_RELEASE);
			return OPENPROCESS_ERROR;
		}
	}
	else
	{
		return VIRTULALLOC_ERROR;
	}

	return RTN_OK;
}

int DumpMemoryRegion(void* addr, DWORD size, int DumpType, BOOL PasteHeaderFromDisk, BOOL bFixHeader, HWND hwndOwner)
{
	HANDLE hProc, hFile;
	DWORD BytesRead, BytesWritten;
	LPVOID BaseAddress;
	OPENFILENAME ofn;
	char szFile[MAX_PATH], szProcName[MAX_PATH];

	BaseAddress = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if(BaseAddress)
	{
		hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, iGlobalPid);
		if(hProc != NULL)
		{
			if(ReadProcessMemory(hProc, (LPVOID)addr, BaseAddress, size, &BytesRead))
			{
				memset(&ofn, 0, sizeof(ofn));

				ofn.lStructSize = sizeof(OPENFILENAME);
				ofn.hwndOwner = hwndOwner;

				GetModuleFileNameEx(hProc, NULL, szProcName, sizeof(szProcName)/sizeof(char));

				if(DumpType == DUMPREGION || DumpType == DUMPPARTIAL)
				{
					ofn.lpstrFilter = TEXT("Dump File *.DMP");
					ofn.lpstrTitle = TEXT("Save memory dump ...");

					sprintf_s(szFile,  sizeof(szFile), "addr=%08X-size=%08X.dmp", (DWORD)addr, (DWORD)size);
					ofn.lpstrFile = szFile;
				}
				else
				{
					ofn.lpstrFilter = TEXT("Executable File *.EXE");
					ofn.lpstrTitle = TEXT("Save full dump ...");

					sprintf_s(szFile, sizeof(szFile), "dump-%s", PathFindFileName(szProcName));
					ofn.lpstrFile = szFile;
				}

				ofn.nMaxFile = sizeof(szFile)/sizeof(*szFile);
				ofn.lpstrFileTitle = NULL;
				ofn.lpstrInitialDir = (LPSTR)NULL;
				ofn.Flags = OFN_SHOWHELP | OFN_OVERWRITEPROMPT;
				
				if(GetSaveFileName(&ofn))
				{
					hFile = CreateFile(ofn.lpstrFile, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
					if(hFile != NULL)
					{
						if(PasteHeaderFromDisk)
							PastePEHeader(hProc, (DWORD)BaseAddress, szProcName);

						if(bFixHeader)
							FixHeader(hProc, (DWORD)BaseAddress, szProcName);

						if(!WriteFile(hFile, BaseAddress, size, &BytesWritten, NULL))
						{
							VirtualFree(BaseAddress, 0, MEM_RELEASE);
							CloseHandle(hProc);
							CloseHandle(hFile);
							return WRITEFILE_ERROR;
						}
						else
						{
							CloseHandle(hFile);
							VirtualFree(BaseAddress, 0, MEM_RELEASE);
							CloseHandle(hProc);

							return RTN_OK;
						}
					}
					else
					{
						VirtualFree((LPVOID)BaseAddress, 0, MEM_RELEASE);
						CloseHandle(hProc);
						return CREATEFILE_ERROR;
					}
				}
				else
				{
					VirtualFree((LPVOID)BaseAddress, 0, MEM_RELEASE);
					CloseHandle(hProc);
					return SAVEDIALOGNOCHOICE;
				}
			}
			else
			{	
				VirtualFree((LPVOID)BaseAddress, 0, MEM_RELEASE);
				CloseHandle(hProc);
				return READPROCESSMEMORY_ERROR;
			}
		}
		else
		{	
			VirtualFree((LPVOID)BaseAddress, 0, MEM_RELEASE);
			return OPENPROCESS_ERROR;
		}
	}
	else
	{
		return VIRTULALLOC_ERROR;
	}

	return RTN_OK;
}

void SetAddrAndSizeEdits(HWND MyhDlg, HWND MyhList, int Pos)
{
	char szAddr[9], szSize[9];

	ListView_GetItemText(MyhList, Pos, ADDR_COLUMN, szAddr, sizeof(szAddr));
	SetDlgItemText(MyhDlg, ADDRESS_EDIT, szAddr);
	
	ListView_GetItemText(MyhList, Pos, SIZE_COLUMN, szSize, sizeof(szSize));
	SetDlgItemText(MyhDlg, SIZE_EDIT, szSize);
}

BOOL IsValidHexString(char* String)
{
	int ordValue, sLen = strlen(String);

	while(sLen > 0)
	{
		ordValue = (int)String[sLen-1];

		if(ordValue >= 0x30 && ordValue <= 0x39)
		{
			sLen--;
		}
		else
		{
			if(ordValue >= 0x41 && ordValue <= 0x46)
			{
				sLen--;
			}
			else
				return FALSE;
		}
	}
	return TRUE;
}

void SortProcListView(HWND MyhList, int iSubItem)
{
	if(iSubItem == PATH_COLUMN)
	{
		if ((PathSortOrder == NO_SORT) || (PathSortOrder == PATH_SORT_DESCENDING))
		{
			ListView_SortItems(MyhList, ListViewProcessesCompareProc, PATH_SORT_ASCENDING);
			UpdatelParam(MyhList);
			PathSortOrder = PATH_SORT_ASCENDING;
		}
		else
		{
			ListView_SortItems(MyhList, ListViewProcessesCompareProc, PATH_SORT_DESCENDING);
			UpdatelParam(MyhList);
			PathSortOrder = PATH_SORT_DESCENDING;
		}
	}
	else
	{
		if(iSubItem == PID_COLUMN)
		{
			if((PidSortOrder == NO_SORT) || (PidSortOrder == PID_SORT_DESCENDING))
			{
				ListView_SortItems(MyhList, ListViewProcessesCompareProc, PID_SORT_ASCENDING);
				UpdatelParam(MyhList);
				PidSortOrder = PID_SORT_ASCENDING;
			}
			else
			{
				ListView_SortItems(MyhList, ListViewProcessesCompareProc, PID_SORT_DESCENDING);
				UpdatelParam(MyhList);
				PidSortOrder = PID_SORT_DESCENDING;
			}
		}
		else
		{
			if(iSubItem == IB_COLUMN)
			{
				if((IbSortOrder == NO_SORT) || (IbSortOrder == IB_SORT_DESCENDING))
				{
					ListView_SortItems(MyhList, ListViewProcessesCompareProc, IB_SORT_ASCENDING);
					UpdatelParam(MyhList);
					IbSortOrder = IB_SORT_ASCENDING;
				}
				else
				{
					ListView_SortItems(MyhList, ListViewProcessesCompareProc, IB_SORT_DESCENDING);
					UpdatelParam(MyhList);
					IbSortOrder = IB_SORT_DESCENDING;
				}
			}
			else
			{
				if(iSubItem == IZ_COLUMN)
				{
					if((IzSortOrder == NO_SORT) || (IzSortOrder == IZ_SORT_DESCENDING))
					{
						ListView_SortItems(MyhList, ListViewProcessesCompareProc, IZ_SORT_ASCENDING);
						UpdatelParam(MyhList);
						IzSortOrder = IZ_SORT_ASCENDING;
					}
					else
					{
						ListView_SortItems(MyhList, ListViewProcessesCompareProc, IZ_SORT_DESCENDING);
						UpdatelParam(MyhList);
						IzSortOrder = IZ_SORT_DESCENDING;
					}
				}
			}
		}
	}
}

int ListView_GetPidFromItem(HWND MyhList, int item)
{
	char szText[MAX_PATH];

	ListView_GetItemText(MyhList, item, 1, szText, sizeof(szText));
	return atoi(szText);
}

void UpdatelParam(HWND MyhList)
{
	int iCount;
	LVITEM lvItem;

	lvItem.mask = LVIF_PARAM;
	lvItem.iSubItem = 0;
	lvItem.iItem = 0;

	iCount = ListView_GetItemCount(MyhList);
	while(iCount > 0)
	{
		lvItem.lParam = lvItem.iItem;
		ListView_SetItem(MyhList, &lvItem);
		lvItem.iItem++;
		iCount--;
	}
}

int CALLBACK ModulesCompareProc(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort)
{
	int retval;
	long num1, num2;
	char szText[MAX_PATH], szText2[MAX_PATH];

	switch(lParamSort)
	{
		case MODULE_NAME_COL_SORT_ASCENDING:
			ListView_GetItemText(hModulesLV, lParam1, MODULE_NAME_COL, szText, sizeof(szText));
			ListView_GetItemText(hModulesLV, lParam2, MODULE_NAME_COL, szText2, sizeof(szText2));

			retval = lstrcmpi(szText, szText2);
			break;

		case MODULE_NAME_COL_SORT_DESCENDING:
			ListView_GetItemText(hModulesLV, lParam1, MODULE_NAME_COL, szText, sizeof(szText));
			ListView_GetItemText(hModulesLV, lParam2, MODULE_NAME_COL, szText2, sizeof(szText2));

			retval = lstrcmpi(szText2, szText);
			break;

		case MODULE_IMAGEBASE_COL_SORT_ASCENDING:
			ListView_GetItemText(hModulesLV, lParam1, MODULE_IMAGEBASE_COL, szText, sizeof(szText));
			ListView_GetItemText(hModulesLV, lParam2, MODULE_IMAGEBASE_COL, szText2, sizeof(szText2));

			num1 = strtol(szText, NULL, 16);
			num2 = strtol(szText2, NULL, 16);

			retval = num1 - num2;
			break;

		case MODULE_IMAGEBASE_COL_SORT_DESCENDING:
			ListView_GetItemText(hModulesLV, lParam1, MODULE_IMAGEBASE_COL, szText, sizeof(szText));
			ListView_GetItemText(hModulesLV, lParam2, MODULE_IMAGEBASE_COL, szText2, sizeof(szText2));

			num1 = strtol(szText, NULL, 16);
			num2 = strtol(szText2, NULL, 16);

			retval = num2 - num1;
			break;

		case MODULE_IMAGESIZE_COL_SORT_ASCENDING:
			ListView_GetItemText(hModulesLV, lParam1, MODULE_IMAGESIZE_COL, szText, sizeof(szText));
			ListView_GetItemText(hModulesLV, lParam2, MODULE_IMAGESIZE_COL, szText2, sizeof(szText2));

			num1 = strtol(szText, NULL, 16);
			num2 = strtol(szText2, NULL, 16);

			retval = num1 - num2;
			break;

		case MODULE_IMAGESIZE_COL_SORT_DESCENDING:
			ListView_GetItemText(hModulesLV, lParam1, MODULE_IMAGESIZE_COL, szText, sizeof(szText));
			ListView_GetItemText(hModulesLV, lParam2, MODULE_IMAGESIZE_COL, szText2, sizeof(szText2));

			num1 = strtol(szText, NULL, 16);
			num2 = strtol(szText2, NULL, 16);

			retval = num2 - num1;
			break;

	}

	return retval;


}
int CALLBACK ThreadsCompareProc(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort)
{
	int retval, num1, num2;
	char szText[MAX_PATH], szText2[MAX_PATH];

	switch(lParamSort)
	{
		case THREAD_ID_SORT_ASCENDING:
			ListView_GetItemText(hThreadsLV, lParam1, THREAD_ID_COL, szText, sizeof(szText));
			ListView_GetItemText(hThreadsLV, lParam2, THREAD_ID_COL, szText2, sizeof(szText2));

			num1 = strtol(szText, NULL, 16);
			num2 = strtol(szText2, NULL, 16);

			retval = num1 - num2;
			break;

		case THREAD_ID_SORT_DESCENDING:
			ListView_GetItemText(hThreadsLV, lParam1, THREAD_ID_COL, szText, sizeof(szText));
			ListView_GetItemText(hThreadsLV, lParam2, THREAD_ID_COL, szText2, sizeof(szText2));

			num1 = strtol(szText, NULL, 16);
			num2 = strtol(szText2, NULL, 16);

			retval = num2 - num1;

			break;

		case THREAD_PRIORITY_SORT_ASCENDING:
			ListView_GetItemText(hThreadsLV, lParam1, THREAD_PRIORITY_COL, szText, sizeof(szText));
			ListView_GetItemText(hThreadsLV, lParam2, THREAD_PRIORITY_COL, szText2, sizeof(szText2));

			num1 = strtol(szText, NULL, 16);
			num2 = strtol(szText2, NULL, 16);

			retval = num1 - num2;
			break;

		case THREAD_PRIORITY_SORT_DESCENDING:
			ListView_GetItemText(hThreadsLV, lParam1, THREAD_PRIORITY_COL, szText, sizeof(szText));
			ListView_GetItemText(hThreadsLV, lParam2, THREAD_PRIORITY_COL, szText2, sizeof(szText2));

			num1 = strtol(szText, NULL, 16);
			num2 = strtol(szText2, NULL, 16);

			retval = num2 - num1;
			break;

		case THREAD_TEB_SORT_ASCENDING:
			ListView_GetItemText(hThreadsLV, lParam1, THREAD_TEB_COL, szText, sizeof(szText));
			ListView_GetItemText(hThreadsLV, lParam2, THREAD_TEB_COL, szText2, sizeof(szText2));

			num1 = strtol(szText, NULL, 16);
			num2 = strtol(szText2, NULL, 16);

			retval = num1 - num2;
			break;

		case THREAD_TEB_SORT_DESCENDING:
			ListView_GetItemText(hThreadsLV, lParam1, THREAD_TEB_COL, szText, sizeof(szText));
			ListView_GetItemText(hThreadsLV, lParam2, THREAD_TEB_COL, szText2, sizeof(szText2));

			num1 = strtol(szText, NULL, 16);
			num2 = strtol(szText2, NULL, 16);

			retval = num2 - num1;
			break;

		case THREAD_START_SORT_ASCENDING:
			ListView_GetItemText(hThreadsLV, lParam1, THREAD_STARTADDRESS_COL, szText, sizeof(szText));
			ListView_GetItemText(hThreadsLV, lParam2, THREAD_STARTADDRESS_COL, szText2, sizeof(szText2));

			num1 = strtol(szText, NULL, 16);
			num2 = strtol(szText2, NULL, 16);

			retval = num1 - num2;
			break;

		case THREAD_START_SORT_DESCENDING:
			ListView_GetItemText(hThreadsLV, lParam1, THREAD_STARTADDRESS_COL, szText, sizeof(szText));
			ListView_GetItemText(hThreadsLV, lParam2, THREAD_STARTADDRESS_COL, szText2, sizeof(szText2));

			num1 = strtol(szText, NULL, 16);
			num2 = strtol(szText2, NULL, 16);

			retval = num2 - num1;
			break;

		case THREAD_STATE_SORT_ASCENDING:
			ListView_GetItemText(hThreadsLV, lParam1, THREAD_STATE_COL, szText, sizeof(szText));
			ListView_GetItemText(hThreadsLV, lParam2, THREAD_STATE_COL, szText2, sizeof(szText2));

			retval = lstrcmpi(szText, szText2);
			break;

		case THREAD_STATE_SORT_DESCENDING:
			ListView_GetItemText(hThreadsLV, lParam1, THREAD_STATE_COL, szText, sizeof(szText));
			ListView_GetItemText(hThreadsLV, lParam2, THREAD_STATE_COL, szText2, sizeof(szText2));

			retval = lstrcmpi(szText2, szText);
			break;

		default: break;
	}

	return retval;
}

int CALLBACK HandlesCompareProc(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort)
{
	int retval, nro1, nro2;
	char szText[MAX_PATH], szText2[MAX_PATH];

	switch(lParamSort)
	{
		case HANDLE_TYPE_COL_SORT_ASCENDING:
			ListView_GetItemText(hHandlesLV, lParam1, HANDLE_TYPE_COL, szText, sizeof(szText));
			ListView_GetItemText(hHandlesLV, lParam2, HANDLE_TYPE_COL, szText2, sizeof(szText2));

			retval = lstrcmpi(szText, szText2);
			break;

		case HANDLE_COL_SORT_ASCENDING:
			ListView_GetItemText(hHandlesLV, lParam1, HANDLE_TYPE_COL, szText, sizeof(szText));
			ListView_GetItemText(hHandlesLV, lParam2, HANDLE_TYPE_COL, szText2, sizeof(szText2));

			nro1 = strtol(szText, 0, 16);
			nro2 = strtol(szText2, 0, 16);

			retval = nro1 - nro2;
			break;

		case HANDLE_COL_SORT_DESCENDING:
			ListView_GetItemText(hHandlesLV, lParam1, HANDLE_TYPE_COL, szText, sizeof(szText));
			ListView_GetItemText(hHandlesLV, lParam2, HANDLE_TYPE_COL, szText2, sizeof(szText2));

			nro1 = strtol(szText, 0, 16);
			nro2 = strtol(szText2, 0, 16);

			retval = nro2 - nro1;
			break;

		case HANDLE_NAME_COL_SORT_ASCENDING:
			ListView_GetItemText(hHandlesLV, lParam1, HANDLE_NAME_COL, szText, sizeof(szText));
			ListView_GetItemText(hHandlesLV, lParam2, HANDLE_NAME_COL, szText2, sizeof(szText2));

			retval = lstrcmpi(szText, szText2);
			break;

		case HANDLE_TYPE_COL_SORT_DESCENDING:
			ListView_GetItemText(hHandlesLV, lParam1, HANDLE_TYPE_COL, szText, sizeof(szText));
			ListView_GetItemText(hHandlesLV, lParam2, HANDLE_TYPE_COL, szText2, sizeof(szText2));

			retval = lstrcmpi(szText2, szText);
			break;

		case HANDLE_NAME_COL_SORT_DESCENDING:
			ListView_GetItemText(hHandlesLV, lParam1, HANDLE_NAME_COL, szText, sizeof(szText));
			ListView_GetItemText(hHandlesLV, lParam2, HANDLE_NAME_COL, szText2, sizeof(szText2));

			retval = lstrcmpi(szText2, szText);
			break;

		default: break;
	}

	return retval;
}

int CALLBACK ListViewProcessesCompareProc(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort)
{
	char szText[MAX_PATH], szText2[MAX_PATH];
	int retval;

	if(lParamSort == PATH_SORT_ASCENDING)
	{	
		ListView_GetItemText(hList, lParam1, PATH_COLUMN, szText, sizeof(szText));
		ListView_GetItemText(hList, lParam2, PATH_COLUMN, szText2, sizeof(szText2));

		retval = lstrcmpi(szText, szText2);
	}
	else
	{
		if(lParamSort == PATH_SORT_DESCENDING)
		{
			ListView_GetItemText(hList, lParam1, PATH_COLUMN, szText, sizeof(szText));
			ListView_GetItemText(hList, lParam2, PATH_COLUMN, szText2, sizeof(szText2));

			retval = lstrcmpi(szText2, szText);
		}
		else
		{
			if(lParamSort == PID_SORT_ASCENDING)
			{
				ListView_GetItemText(hList, lParam1, PID_COLUMN, szText, sizeof(szText));
				ListView_GetItemText(hList, lParam2, PID_COLUMN, szText2, sizeof(szText2));

				int num1 = atoi(szText);
				int num2 = atoi(szText2);

				retval = num1 - num2;
			}
			else
			{
				if(lParamSort == PID_SORT_DESCENDING)
				{
					ListView_GetItemText(hList, lParam1, PID_COLUMN, szText, sizeof(szText));
					ListView_GetItemText(hList, lParam2, PID_COLUMN, szText2, sizeof(szText2));

					int num1 = atoi(szText);
					int num2 = atoi(szText2);

					retval = num2 - num1;
				}
				else
				{
					if(lParamSort == IB_SORT_ASCENDING)
					{
						ListView_GetItemText(hList, lParam1, IB_COLUMN, szText, sizeof(szText));
						ListView_GetItemText(hList, lParam2, IB_COLUMN, szText2, sizeof(szText2));

						long num1 = strtol(szText, NULL, 16);
						long num2 = strtol(szText2, NULL, 16);

						retval = num1 - num2;
					}
					else
					{
						if(lParamSort == IB_SORT_DESCENDING)
						{
							ListView_GetItemText(hList, lParam1, IB_COLUMN, szText, sizeof(szText));
							ListView_GetItemText(hList, lParam2, IB_COLUMN, szText2, sizeof(szText2));

							long num1 = strtol(szText, NULL, 16);
							long num2 = strtol(szText2, NULL, 16);

							retval = num2 - num1;
						}
						else
						{
							if(lParamSort == IZ_SORT_ASCENDING)
							{
								ListView_GetItemText(hList, lParam1, IZ_COLUMN, szText, sizeof(szText));
								ListView_GetItemText(hList, lParam2, IZ_COLUMN, szText2, sizeof(szText2));

								long num1 = strtol(szText, NULL, 16);
								long num2 = strtol(szText2, NULL, 16);

								retval = num1 - num2;
							}
							else
							{
								ListView_GetItemText(hList, lParam1, IZ_COLUMN, szText, sizeof(szText));
								ListView_GetItemText(hList, lParam2, IZ_COLUMN, szText2, sizeof(szText2));

								long num1 = strtol(szText, NULL, 16);
								long num2 = strtol(szText2, NULL, 16);

								retval = num2 - num1;
							}
						}
					}

				}
			}
		}
	}

	return retval;
}

void SelectAllItems(HWND MyhList)
{
	int index, iCount;

	iCount = ListView_GetItemCount(MyhList);
	for(index = 0; index < iCount; index++)
		ListView_SetItemState(MyhList, index, LVIS_FOCUSED | LVIS_SELECTED, 0x000F);
}

//void SetHotKey(WORD Key, WORD KeyId, BYTE fVirt)
//{
//	if(hAccel != NULL)
//		DestroyAcceleratorTable(hAccel);
//
//	MyAccel.fVirt = fVirt; //FCONTROL | FVIRTKEY | FNOINVERT;
//	MyAccel.key = LOBYTE(Key);
//	MyAccel.cmd = KeyId;
//
//	hAccel = CreateAcceleratorTable(&MyAccel, 1);
//	if(hAccel == NULL)
//		MessageBox(NULL, TEXT("Couldn't create accelerator table!"), TEXT("Ups!"), MB_ICONERROR);
//}

void MySetClipboardData(void* pMem, SIZE_T size)
{
	HGLOBAL hGlobal;
	HANDLE Address;

	hGlobal = GlobalAlloc(GHND, size);
	Address = GlobalLock(hGlobal);

	memcpy_s(Address, size, pMem, size);
	//GlobalUnlock(hGlobal);

	if(OpenClipboard(NULL))
	{
		EmptyClipboard();
		SetClipboardData(CF_TEXT, hGlobal);
		GlobalUnlock(hGlobal);
		CloseClipboard();
	}

	//GlobalFree(hGlobal);
}

void CopyDataToClipBoard(HWND MyhList, int MaxCols)
{
	int iCount, iPos, count, index, delta;
	int* m_buffer;
	int* m_aux_buffer;
	SIZE_T m_size;
	WORD enter = 0x0a0d;
	BYTE null = 0;

	// first, we need to know how many items were selected
	iCount = ListView_GetSelectedCount(MyhList);

	if(iCount > 0)
	{
		// we allocate memory to store the text of every item
		// the size of the malloc chunk is iCount*MAX_COLS*MAX_PATH
		m_size = iCount*MaxCols*MAX_PATH;
		m_buffer = (int*)malloc(m_size);
		
		m_aux_buffer = m_buffer;

		if(m_buffer)
		{
			// second, we need to know which is the first selected item
			iPos = ListView_GetNextItem(MyhList, -1, LVNI_SELECTED);
			if(iPos != -1)
			{
				count = 0;
				while(count < iCount)
				{
					for(index = 0; index < MaxCols; index++)
					{
						ListView_GetItemText(MyhList, iPos, index, (LPSTR)m_buffer, m_size);

						// adjust the m_buffer pointer
						m_buffer = (int*)((int)m_buffer + (int)strlen((char*)m_buffer)); 
						
						delta = (int)m_buffer - (int)m_aux_buffer;
						
						// append a space char to the string
						strncat_s((char*)m_buffer, m_size - delta, " ", 1);
						// increment the m_buffer pointer to point to the last char
						m_buffer = (int*)((int)m_buffer + 1);
					}

					delta = (int)m_buffer - (int)m_aux_buffer;
					// append a line break at the end of the string
					memcpy_s((void*)m_buffer, m_size - delta, &enter, sizeof(enter));
					m_buffer = (int*)((int)m_buffer + 2);
					
					// increment the loop counter
					count++;

					// get next item position in the listview
					iPos = ListView_GetNextItem(MyhList, iPos, LVNI_SELECTED);
				}
			}

			// append a null char at the end of the buffer to indicate the end of the string
			delta = (int)m_buffer - (int)m_aux_buffer;
			memcpy_s((void*)m_buffer, m_size - delta, &null, sizeof(null));

			MySetClipboardData(m_aux_buffer, m_size);

			free(m_aux_buffer);
		}
		else
			MessageBox(NULL, TEXT("Couldn't not allocate memory!"), TEXT("malloc failed!"), MB_ICONERROR);
	}
}

void ShowAboutInfo(HWND hDlg)
{
	MessageBox(hDlg, TEXT("Virtual Section Dumper v2.0\n\nCoded by:\n\t +NCR/CRC! [ReVeRsEr]\n\ncrackinglandia(at)gmail(dot)com\n@crackinglandia\n\nGeneral Pico, La Pampa\nArgentina"), 
		TEXT("Virtual Section Dumper v2.0"),
		MB_ICONINFORMATION);
}

HWND PopulateHandlesLV(HWND hDlg)
{
	HWND hMyList;

	hMyList = GetDlgItem(hDlg, HANDLESLV);

	if(hMyList)
	{
		/*
			ComCtl32.dll version 6 has problems with LVS_EX_GRIDLINES when its scrolled vertically.
			An option to avoid this issue is to disable the LVS_EX_GRIDLINES style.
			Another option is to disable the Windows XP Style.

			* http://stackoverflow.com/questions/1416793/listview-gridlines-issue
			* http://www.ureader.com/msg/1484143.aspx
		*/
		ListView_SetExtendedListViewStyle(hMyList, LVS_EX_GRIDLINES | LVS_EX_FULLROWSELECT | LVS_SORTASCENDING);
		
		CreateColumnsHandlesLV(hMyList);
		EnumProcessHandles(hMyList);
	}

	return hMyList;
}

/*
 this code was taken from http://forum.sysinternals.com/uploads/26792/handles.zip
 more information: http://forum.sysinternals.com/howto-enumerate-handles_topic18892.html
*/
int EnumProcessHandles(HWND MyhList)
{
	NTSTATUS status;
	PSYSTEM_HANDLE_INFORMATION handleInfo;
	ULONG handleInfoSize = 0x10000;
	HANDLE processHandle;
	ULONG i, iCount = 0;
	LVITEM lvItem;
	char szText[MAX_PATH];

    if (!(processHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, iGlobalPid)))
    {
        return RTN_ERROR;
    }

    handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);

    /* NtQuerySystemInformation won't give us the correct buffer size, 
       so we guess by doubling the buffer size. */
    while ((status = NtQuerySystemInformation(
        SystemHandleInformation,
        handleInfo,
        handleInfoSize,
        NULL
        )) == STATUS_INFO_LENGTH_MISMATCH)
        handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);

    /* NtQuerySystemInformation stopped giving us STATUS_INFO_LENGTH_MISMATCH. */
    if (!NT_SUCCESS(status))
        return RTN_ERROR;

    for (i = 0; i < handleInfo->HandleCount; i++)
    {
        SYSTEM_HANDLE handle = handleInfo->Handles[i];
        HANDLE dupHandle = NULL;
        POBJECT_TYPE_INFORMATION objectTypeInfo;
        PVOID objectNameInfo;
        UNICODE_STRING objectName;
        ULONG returnLength;

        /* Check if this handle belongs to the PID the user specified. */
        if (handle.ProcessId != (ULONG)iGlobalPid)
            continue;

        /* Duplicate the handle so we can query it. */
        if (!NT_SUCCESS(NtDuplicateObject(
            processHandle,
            (HANDLE)handle.Handle,
            GetCurrentProcess(),
            &dupHandle,
            0,
            0,
            0
            )))
        {
            continue;
        }

        /* Query the object type. */
        objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x1000);
        if (!NT_SUCCESS(NtQueryObject(
            dupHandle,
            ObjectTypeInformation,
            objectTypeInfo,
            0x1000,
            NULL
            )))
        {
            CloseHandle(dupHandle);
            continue;
        }

        /* Query the object name (unless it has an access of 
           0x0012019f, on which NtQueryObject could hang. */
        if (handle.GrantedAccess == 0x0012019f)
        {
            free(objectTypeInfo);
            CloseHandle(dupHandle);
            continue;
        }

        objectNameInfo = malloc(0x1000);
        if (!NT_SUCCESS(NtQueryObject(
            dupHandle,
            ObjectNameInformation,
            objectNameInfo,
            0x1000,
            &returnLength
            )))
        {
            /* Reallocate the buffer and try again. */
            objectNameInfo = realloc(objectNameInfo, returnLength);
            if (!NT_SUCCESS(NtQueryObject(
                dupHandle,
                ObjectNameInformation,
                objectNameInfo,
                returnLength,
                NULL
                )))
            {
                free(objectTypeInfo);
                free(objectNameInfo);
                CloseHandle(dupHandle);
                continue;
            }
        }

        /* Cast our buffer into an UNICODE_STRING. */
        objectName = *(PUNICODE_STRING)objectNameInfo;

        /* Print the information! */
        if (objectName.Length)
        {
			memset(&lvItem, 0, sizeof(lvItem));

			lvItem.mask = LVIF_TEXT | LVIF_PARAM;
			lvItem.cchTextMax = MAX_PATH;
			lvItem.iItem = lvItem.lParam = iCount;
			lvItem.iSubItem = 0;

			if(ListView_InsertItem(MyhList, &lvItem) != -1)
			{
				sprintf_s(szText, sizeof(szText), "%.*S", objectTypeInfo->Name.Length / 2, objectTypeInfo->Name.Buffer);
				ListView_SetItemText(MyhList, iCount, HANDLE_TYPE_COL, szText);
				
				sprintf_s(szText, sizeof(szText), "%.*S", objectName.Length / 2, objectName.Buffer);
				ListView_SetItemText(MyhList, iCount, HANDLE_NAME_COL, szText);

				sprintf_s(szText, sizeof(szText), "%08X", handle.Handle);
				ListView_SetItemText(MyhList, iCount, HANDLE_COL, szText);
				iCount++;
			}
			else
			{
				MessageBox(NULL, TEXT("Couldn't insert item!"), TEXT("Ups!"), MB_ICONERROR);
			}
        }
		else
		{
			// we also display those object we couldn't resolve the name
			memset(&lvItem, 0, sizeof(lvItem));

			lvItem.mask = LVIF_TEXT | LVIF_PARAM;
			lvItem.cchTextMax = MAX_PATH;
			lvItem.iItem = lvItem.lParam = iCount;
			lvItem.iSubItem = 0;

			if(ListView_InsertItem(MyhList, &lvItem) != -1)
			{
				sprintf_s(szText, sizeof(szText), "%.*S", objectTypeInfo->Name.Length / 2, objectTypeInfo->Name.Buffer);
				ListView_SetItemText(MyhList, iCount, HANDLE_TYPE_COL, szText);
				
				ListView_SetItemText(MyhList, iCount, HANDLE_NAME_COL, "(unnamed)");
				
				sprintf_s(szText, sizeof(szText), "%08X", handle.Handle);
				ListView_SetItemText(MyhList, iCount, HANDLE_COL, szText);

				iCount++;
			}
			else
			{
				MessageBox(NULL, TEXT("Couldn't insert item!"), TEXT("Ups!"), MB_ICONERROR);
			}
		}

        free(objectTypeInfo);
        free(objectNameInfo);
        CloseHandle(dupHandle);
    }

    free(handleInfo);
    CloseHandle(processHandle);

	return RTN_OK;
}

HWND PopulateRegionLV(HWND hDlg)
{
	HWND hMyList;

	hMyList = GetDlgItem(hDlg, LV_REGIONS);

	if(hMyList)
	{
		/*
			ComCtl32.dll version 6 has problems with LVS_EX_GRIDLINES when its scrolled vertically.
			An option to avoid this issue is to disable the LVS_EX_GRIDLINES style.
			Another option is to disable the Windows XP Style.

			* http://stackoverflow.com/questions/1416793/listview-gridlines-issue
			* http://www.ureader.com/msg/1484143.aspx
		*/
		ListView_SetExtendedListViewStyle(hMyList, LVS_EX_GRIDLINES | LVS_EX_FULLROWSELECT | LVS_SORTASCENDING);
		
		CreateColumnsRegionLV(hMyList);
		EnumRegions(hMyList);
	}

	return hMyList;
}

void lowercase(char string[])
{
   int  i = 0;
   while(string[i])
   {
      string[i] = tolower(string[i]);
      i++;
   }
}

void CreateColumnsHandlesLV(HWND MyhList)
{
	int index;
	LVCOLUMN lvCol = {0};
	char* lvColTitles[] = {"Type", "Name", "Handle"};
	char szFmtText[MAX_PATH];

	for(index = 0; index < 3; index++)
	{
		lvCol.mask = LVCF_TEXT | LVCF_SUBITEM | LVCF_WIDTH | LVCF_IDEALWIDTH;
		lvCol.pszText = lvColTitles[index];
		
		if(index)
			lvCol.cx = lvCol.cxIdeal = 400;
		else
			lvCol.cx = lvCol.cxIdeal = 100;

		lvCol.cchTextMax = strlen(lvColTitles[index]);

		if(ListView_InsertColumn(MyhList, index, &lvCol) == -1)
		{
			sprintf_s(szFmtText, sizeof(szFmtText), "Couldn't insert column %d", index);
			MessageBox(MyGetWindowOwner(MyhList), szFmtText, TEXT("Ups!"), MB_ICONERROR);
		}
	}
}

void CreateColumnsRegionLV(HWND MyhList)
{
	int index;
	LVCOLUMN lvCol = {0};
	char* lvColTitles[] = {"Address", "Size", "Protect", "State", "Type"};
	char szFmtText[MAX_PATH];

	for(index = 0; index < MAX_COLSREG; index++)
	{
		lvCol.mask = LVCF_TEXT | LVCF_SUBITEM | LVCF_WIDTH | LVCF_IDEALWIDTH;
		lvCol.pszText = lvColTitles[index];
		
		lvCol.cx = lvCol.cxIdeal = 100;

		lvCol.cchTextMax = strlen(lvColTitles[index]);

		if(ListView_InsertColumn(MyhList, index, &lvCol) == -1)
		{
			sprintf_s(szFmtText, sizeof(szFmtText), "Couldn't insert column %d", index);
			MessageBox(MyGetWindowOwner(MyhList), szFmtText, TEXT("Ups!"), MB_ICONERROR);
		}
	}
}

void EnumRegions(HWND MyhList)
{
	HANDLE hProc;
	MEMORY_BASIC_INFORMATION mbi;
	SIZE_T numBytes;
	DWORD MyAddress = 0;
	LVITEM lvItem;
	int index = 0;
	char szText[15];

	hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, iGlobalPid);
	if(hProc != NULL)
	{
		do
		{
			numBytes = VirtualQueryEx(hProc, (LPCVOID)MyAddress, &mbi, sizeof(mbi));

			memset(&lvItem, 0, sizeof(lvItem));

			lvItem.mask = LVIF_TEXT | LVIF_PARAM;
			lvItem.cchTextMax = MAX_PATH;
			lvItem.iItem = lvItem.lParam = index;
			lvItem.iSubItem = 0;

			if(ListView_InsertItem(MyhList, &lvItem) != -1)
			{
				sprintf_s(szText, sizeof(szText), "%08X", (DWORD)mbi.BaseAddress);
				ListView_SetItemText(MyhList, index, 0, szText);

				sprintf_s(szText, sizeof(szText), "%08X", (DWORD)mbi.RegionSize);
				ListView_SetItemText(MyhList, index, 1, szText);
				
				// -----------------------------------------------------

				if(mbi.State == MEM_COMMIT)
				{
					ListView_SetItemText(MyhList, index, 3, "COMMIT");
				}
				else
				{
					if(mbi.State == MEM_RESERVE)
					{
						ListView_SetItemText(MyhList, index, 3, "RESERVE");
					}
					else
					{
						if(mbi.State == MEM_FREE)
							ListView_SetItemText(MyhList, index, 3, "FREE");
					}
				}

				// -----------------------------------------------------

				if(mbi.Type == MEM_IMAGE)
				{
					ListView_SetItemText(MyhList, index, 4, "IMAGE");
				}
				else
				{
					if(mbi.Type == MEM_MAPPED)
					{
						ListView_SetItemText(MyhList, index, 4, "MAPPED");
					}
					else
					{
						if(mbi.Type == MEM_PRIVATE)
						{
							ListView_SetItemText(MyhList, index, 4, "PRIVATE");
						}
						else
						{
							ListView_SetItemText(MyhList, index, 4, "NONE");
						}
					}
				}

				// -----------------------------------------------------

				if(mbi.Protect == PAGE_EXECUTE)
				{
					ListView_SetItemText(MyhList, index, 2, "EXECUTE");
				}
				else
				{
					if(mbi.Protect == PAGE_EXECUTE_READ)
					{
						ListView_SetItemText(MyhList, index, 2, "EXECUTE READ");
					}
					else
					{
						if(mbi.Protect == PAGE_EXECUTE_READWRITE)
						{
							ListView_SetItemText(MyhList, index, 2, "EXECUTE READ/WRITE");
						}
						else
						{
							if(mbi.Protect == PAGE_EXECUTE_WRITECOPY)
							{
								ListView_SetItemText(MyhList, index, 2, "EXECUTE WRITE COPY");
							}
							else
							{
								if(mbi.Protect == PAGE_NOACCESS)
								{
									ListView_SetItemText(MyhList, index, 2, "NO ACCESS");
								}
								else
								{
									if(mbi.Protect == PAGE_READONLY)
									{
										ListView_SetItemText(MyhList, index, 2, "READ ONLY");
									}
									else
									{
										if(mbi.Protect == PAGE_READWRITE)
										{
											ListView_SetItemText(MyhList, index, 2, "READ/WRITE");
										}
										else
										{
											if(mbi.Protect == PAGE_WRITECOPY)
											{
												ListView_SetItemText(MyhList, index, 2, "WRITE COPY");
											}
											else
											{
												if(mbi.Protect == PAGE_GUARD)
												{
													ListView_SetItemText(MyhList, index, 2, "PAGE GUARD");
												}
												else
												{
													if(mbi.Protect == PAGE_NOCACHE)
													{
														ListView_SetItemText(MyhList, index, 2, "NO CACHE");
													}
													else
													{
														if(mbi.Protect == PAGE_WRITECOMBINE)
														{
															ListView_SetItemText(MyhList, index, 2, "WRITE COMBINE");
														}
														else
														{
															ListView_SetItemText(MyhList, index, 2, "NONE");
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}

			}
			else
				MessageBox(MyGetWindowOwner(MyhList), TEXT("Couldn't not insert Item"), TEXT("Ups!"), MB_ICONERROR);

			MyAddress += mbi.RegionSize;
			index++;
		}
		while(numBytes);
	}

	// remove the last item in the listview because it's duplicated
	// becase of the do...while(). It's added twice.
	ListView_DeleteItem(MyhList, ListView_GetItemCount(MyhList) - 1);	
}

// http://msdn.microsoft.com/en-us/library/windows/desktop/ms684139%28v=vs.85%29.aspx
BOOL IsWow64(HANDLE hProc)
{
    BOOL bIsWow64 = FALSE;

    //IsWow64Process is not available on all supported versions of Windows.
    //Use GetModuleHandle to get a handle to the DLL that contains the function
    //and GetProcAddress to get a pointer to the function if available.

    fnIsWow64Process = (LPFN_ISWOW64PROCESS) GetProcAddress(
        GetModuleHandle(TEXT("kernel32")),"IsWow64Process");

    if(NULL != fnIsWow64Process)
    {
        if (!fnIsWow64Process(hProc,&bIsWow64))
        {
            //handle error
        }
    }
    return bIsWow64;
}

void RefreshLV(HWND hWinDlg, HWND myListHandle)
{
	ListView_DeleteAllItems(myListHandle);
	ListProcesses(hWinDlg, myListHandle);
}

BOOL CALLBACK AppDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	DWORD SelItem, iPid;
	HANDLE hProc;
	char szAddr[9], szSize[9];
	int retval;

	switch(uMsg)
	{
		case WM_NOTIFY:
			switch(LOWORD(wParam))
			{
				case LV_PROCESSES:
					switch(((LPNMHDR)lParam)->code)
					{
						case NM_DBLCLK:
							item = ListView_GetNextItem(hList, -1, LVNI_SELECTED); 

							if(item != -1)
							{
							
								iPid = ListView_GetPidFromItem(hList, item);

								hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, iPid);
								if(hProc != NULL)
								{
									if((RunningOnWow64 && IsWow64(hProc)) || !RunningOnWow64)
									{
										CloseHandle(hProc);
										
										iGlobalPid = iPid;

										ListView_GetItemText(hList, item, PATH_COLUMN, szCaption, sizeof(szCaption));

										DialogBoxParam(hGlobalInstance, (LPCTSTR)SECTIONSDLG, hDlg, DumpRegionProc, 0);
									}
									else
									{
										CloseHandle(hProc);
										MessageBox(hDlg, TEXT("The selected item is not a 32 bits process"), TEXT("Ups!"), MB_ICONERROR);
									}
								}
								else
									MessageBox(hDlg, TEXT("Couldn't not receive process handle!"), TEXT("VSD v2.0"), MB_ICONERROR);
							}
							break;
						
						case LVN_COLUMNCLICK:
							{
								NMLISTVIEW* pListView = (NMLISTVIEW*)lParam;
								SortProcListView(hList, pListView->iSubItem);
							}
							break;
						
						default: break;
					}
					break;

				default: break;
			}
			return 0;

		case WM_INITDIALOG:
			SendMessage(hDlg, WM_SETICON, ICON_SMALL, (LPARAM)LoadIcon(hGlobalInstance, MAKEINTRESOURCE(LIST_ICON)));
			SendMessage(hDlg, WM_SETICON, ICON_BIG, (LPARAM)LoadIcon(hGlobalInstance, MAKEINTRESOURCE(LIST_ICON)));

			//RegisterHotKey(hDlg, HOTKEY_CTRL_C, MOD_CONTROL, CTRL_C);
			//RegisterHotKey(hDlg, HOTKEY_CTRL_A, MOD_CONTROL, CTRL_A);
			//RegisterHotKey(hDlg, HOTKEY_CTRL_R, MOD_CONTROL, CTRL_R);
			//RegisterHotKey(hDlg, HOTKEY_SHIFT_DEL, MOD_SHIFT, VK_DELETE);

			InitCommonCtrlsEx();

			// create popup menu for the listview
			hMainMenu = CreatePopupMenu();
			AppendMenu(hMainMenu, MF_STRING, IDM_SELECTALL, TEXT("Select &All"));
			AppendMenu(hMainMenu, MF_STRING, IDM_COPY2CLIPBOARD, TEXT("&Copy to Clipboard"));
			
			InsertMenu(hMainMenu, 2, MF_SEPARATOR, 0, "-");

			hDumpSubMenu = CreatePopupMenu();
			InsertMenu(hMainMenu, 2, MF_POPUP, (UINT)hDumpSubMenu, TEXT("&Dump"));
			AppendMenu(hDumpSubMenu, MF_STRING, IDM_DUMP_FULL, TEXT("&Full"));
			AppendMenu(hDumpSubMenu, MF_STRING, IDM_DUMP_PARTIAL, TEXT("&Partial"));
			AppendMenu(hDumpSubMenu, MF_STRING, IDM_DUMP_REGION, TEXT("&Regions"));
			InsertMenu(hMainMenu, 2, MF_SEPARATOR, 0, "-");

			// create a sub-menu
			hViewSubMenu = CreatePopupMenu();
			InsertMenu(hMainMenu, 2, MF_POPUP, (UINT)hViewSubMenu, TEXT("&View"));
			AppendMenu(hViewSubMenu, MF_STRING, IDM_LIST_MODULES, TEXT("&Modules"));
			AppendMenu(hViewSubMenu, MF_STRING, IDM_LIST_HANDLES, TEXT("&Handles"));
			AppendMenu(hViewSubMenu, MF_STRING, IDM_LIST_THREADS, TEXT("&Threads"));

			InsertMenu(hMainMenu, 2, MF_SEPARATOR, 0, "-");

			AppendMenu(hMainMenu, MF_STRING, IDM_PATCH_PROCESS, TEXT("&Patch ..."));

			InsertMenu(hMainMenu, 2, MF_SEPARATOR, 0, "-");

			AppendMenu(hMainMenu, MF_STRING, IDM_DELPROCESS, TEXT("&Kill Process"));
			
			InsertMenu(hMainMenu, 2, MF_SEPARATOR, 0, "-");
			
			AppendMenu(hMainMenu, MF_STRING, IDM_REFRESH, TEXT("&Refresh"));

			if(AdjustPrivileges() == RTN_OK)
			{
				HasPrivileges = TRUE;
			}
			else
			{
				HasPrivileges = FALSE;
				MessageBox(NULL, TEXT("WARNING!: SetPrivilege could not be set!!!\n\nSome process information may not be available!, some processes may not be displayed or some information could be inaccurate!"), TEXT("Ups!"), MB_ICONERROR);
			}

			// we test if our process is running under WoW to see we need to 
			// check or not the EXCLUDE_X64_CHECKBOX button
			ExcludeWow64CheckBox = GetDlgItem(hDlg, EXCLUDE_X64_PROCS);
			
			// do we have a valid HWND?
			if(ExcludeWow64CheckBox)
			{
				// if so, test if we are running in WoW
				if(!IsWow64(GetCurrentProcess()))
				{
					RunningOnWow64 = FALSE;
					// disable the checkbox (it has no sense to mantain this button enable under x86 OSes)
					Button_Enable(ExcludeWow64CheckBox, FALSE);
				}
				else
				{
					RunningOnWow64 = TRUE;
					
					if(HasPrivileges)
					{
						// else, activate the checkbox and check it by default!
						Button_Enable(ExcludeWow64CheckBox, TRUE);
						CheckDlgButton(hDlg, EXCLUDE_X64_PROCS, BST_CHECKED);
					}
					else
					{
						Button_Enable(ExcludeWow64CheckBox, FALSE);
						CheckDlgButton(hDlg, EXCLUDE_X64_PROCS, BST_UNCHECKED);
					}
				}
			}

			hList = PopulateListView(hDlg);
			
			//SendMessage(hDlg, DM_SETDEFID, (WPARAM)LV_PROCESSES, TRUE);
			//SendMessage(hDlg, WM_NEXTDLGCTL, (WPARAM)LV_PROCESSES, TRUE);

			//SetHotKey(CTRL_C, HOTKEY_CTRL_C, FCONTROL | FVIRTKEY | FNOINVERT);
			//SendDlgItemMessage(hDlg, LV_REGIONS, HKM_SETHOTKEY, CTRL_C, 0);
			
			CheckDlgButton(hDlg, FIXPEHEADER, BST_CHECKED);

			return 0;

		case WM_CONTEXTMENU:
			GetCursorPos(&pt);
			SelItem = TrackPopupMenuEx(hMainMenu, TPM_RETURNCMD, pt.x, pt.y, hDlg, NULL);

			switch(SelItem)
			{
				case IDM_DELPROCESS:
					item = ListView_GetNextItem(hList, -1, LVNI_SELECTED);
					if(item != -1)
					{
						if(MessageBox(hDlg, TEXT("Are you sure you want to kill the process?"), TEXT("Terminate Process"), MB_YESNO) == IDYES)
						{
							iPid = ListView_GetPidFromItem(hList, item);
							hProc = OpenProcess(PROCESS_TERMINATE, FALSE, iPid);
							if(hProc != NULL)
							{
								if((RunningOnWow64 && IsWow64(hProc)) || !RunningOnWow64)
								{
									// terminate the process
									TerminateProcess(hProc, 0);

									// update the processes listview
									Sleep(500);
									RefreshLV(hDlg, hList);
									//ListView_DeleteAllItems(hList);
									//ListProcesses(hDlg, hList);
								}
								else
								{
									MessageBox(hDlg, TEXT("The selected item is not a 32 bits process"), TEXT("Ups!"), MB_ICONERROR);
								}
								CloseHandle(hProc);
							}
							else
								MessageBox(hDlg, TEXT("Couldn't terminate process!"), TEXT("Terminate Process"), MB_ICONERROR);
						}
					}
					break;

				case IDM_REFRESH:
					//ListView_DeleteAllItems(hList);
					//ListProcesses(hDlg, hList);
					RefreshLV(hDlg, hList);
					break;

				case IDM_LIST_MODULES:
					item = ListView_GetNextItem(hList, -1, LVNI_SELECTED);
					if(item != -1)
					{
						iPid = ListView_GetPidFromItem(hList, item);
						hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, iPid);
						if(hProc != NULL)
						{
							if((RunningOnWow64 && IsWow64(hProc)) || !RunningOnWow64)
							{
								iGlobalPid = iPid;
								
								bGlobalPastePEHeader = IsDlgButtonChecked(hDlg, PASTEPEHEADER);
								bGlobalFixHeader = IsDlgButtonChecked(hDlg, FIXPEHEADER);

								//ListView_GetItemText(hList, item, IB_COLUMN, szAddr, sizeof(szAddr));
								//ListView_GetItemText(hList, item, IZ_COLUMN, szSize, sizeof(szSize));

								//RegionAddr = strtol(szAddr, 0, 16);
								//RegionSize = strtol(szSize, 0, 16);

								ListView_GetItemText(hList, item, PATH_COLUMN, szCaption, sizeof(szCaption));

								DialogBoxParam(hGlobalInstance, (LPCTSTR)MODULESDLG, hDlg, EnumModulesDlgProc, 0);
								//RefreshLV(hDlg, hList);
							}
							else
							{
								MessageBox(hDlg, TEXT("The selected item is not a 32 bits process"), TEXT("Ups!"), MB_ICONERROR);
							}
							CloseHandle(hProc);
						}
						else
						{
							MessageBox(hDlg, TEXT("Couldn't receive process handle!"), TEXT("VSD v2.0"), MB_ICONERROR);
						}
					}
					break;

				case IDM_LIST_THREADS:
					item = ListView_GetNextItem(hList, -1, LVNI_SELECTED); 

					if(item != -1)
					{
						iPid = ListView_GetPidFromItem(hList, item);

						hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, iPid);
						if(hProc != NULL)
						{
							if((RunningOnWow64 && IsWow64(hProc)) || !RunningOnWow64)
							{			
								iGlobalPid = iPid;

								ListView_GetItemText(hList, item, PATH_COLUMN, szCaption, sizeof(szCaption));

								DialogBoxParam(hGlobalInstance, (LPCTSTR)THREADSDLG, hDlg, ThreadsDlgProc, 0);
							}
							else
							{
								MessageBox(hDlg, TEXT("The selected item is not a 32 bits process"), TEXT("Ups!"), MB_ICONERROR);
							}
							
							CloseHandle(hProc);
						}
						else
							MessageBox(hDlg, TEXT("Couldn't not receive process handle!"), TEXT("VSD v2.0"), MB_ICONERROR);
					}
					break;

				case IDM_LIST_HANDLES:
					item = ListView_GetNextItem(hList, -1, LVNI_SELECTED);
					if(item != -1)
					{
						iPid = ListView_GetPidFromItem(hList, item);
						hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, iPid);
						if(hProc != NULL)
						{
							if((RunningOnWow64 && IsWow64(hProc)) || !RunningOnWow64)
							{
								iGlobalPid = iPid;

								ListView_GetItemText(hList, item, PATH_COLUMN, szCaption, sizeof(szCaption));

								DialogBoxParam(hGlobalInstance, (LPCTSTR)HANDLESDLG, hDlg, EnumHandlesDlgProc, 0);
							}
							else
							{
								MessageBox(hDlg, TEXT("The selected item is not a 32 bits process"), TEXT("Ups!"), MB_ICONERROR);
							}
							
							CloseHandle(hProc);
						}
						else
						{
							MessageBox(hDlg, TEXT("Couldn't receive process handle!"), TEXT("VSD v2.0"), MB_ICONERROR);
						}
					}
					break;

				case IDM_DUMP_PARTIAL:
					item = ListView_GetNextItem(hList, -1, LVNI_SELECTED);
					if(item != -1)
					{
						iPid = ListView_GetPidFromItem(hList, item);
						hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, iPid);
						if(hProc != NULL)
						{
							if((RunningOnWow64 && IsWow64(hProc)) || !RunningOnWow64)
							{
								ListView_GetItemText(hList, item, IB_COLUMN, szAddr, sizeof(szAddr));
								ListView_GetItemText(hList, item, IZ_COLUMN, szSize, sizeof(szSize));

								RegionAddr = strtol(szAddr, 0, 16);
								RegionSize = strtol(szSize, 0, 16);

								iGlobalPid = iPid;
								
								ListView_GetItemText(hList, item, PATH_COLUMN, szCaption, sizeof(szCaption));

								DialogBoxParam(hGlobalInstance, (LPCTSTR)PARTIALDUMP, hDlg, PartialDumpProc, 0);
							}
							else
							{
								MessageBox(hDlg, TEXT("The selected item is not a 32 bits process"), TEXT("Ups!"), MB_ICONERROR);
							}
							CloseHandle(hProc);
						}
						else
						{
							MessageBox(hDlg, TEXT("Couldn't receive process handle!"), TEXT("VSD v2.0"), MB_ICONERROR);
						}
					}
					break;

				case IDM_DUMP_FULL:
					item = ListView_GetNextItem(hList, -1, LVNI_SELECTED);
										
					if( item != -1)
					{
						iPid = ListView_GetPidFromItem(hList, item);
						hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, iPid);
						if(hProc != NULL)
						{
							if((RunningOnWow64 && IsWow64(hProc)) || !RunningOnWow64)
							{
								iGlobalPid = iPid;
								
								ListView_GetItemText(hList, item, IB_COLUMN, szAddr, sizeof(szAddr));
								ListView_GetItemText(hList, item, IZ_COLUMN, szSize, sizeof(szSize));

								BOOL bPasteHeader = IsDlgButtonChecked(hDlg, PASTEPEHEADER);
								BOOL bFixHeader = IsDlgButtonChecked(hDlg, FIXPEHEADER);

								retval = DumpMemoryRegion((void*)strtol(szAddr, NULL, 16), strtol(szSize, NULL, 16), DUMPFULL, bPasteHeader, bFixHeader,  hDlg);

								ValidateResult(retval);
							}
							else
							{
								MessageBox(hDlg, TEXT("The selected item is not a 32 bits process"), TEXT("Ups!"), MB_ICONERROR);
							}
							CloseHandle(hProc);
						}
						else
							MessageBox(hDlg, TEXT("Couldn't receive process handle!"), TEXT("VSD v2.0"), MB_ICONERROR);
					}
					break;

				case IDM_DUMP_REGION:
					item = ListView_GetNextItem(hList, -1, LVNI_SELECTED);

					if( item!= -1)
					{
						DWORD iPid = ListView_GetPidFromItem(hList, item);
						hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, iPid);
						if(hProc != NULL)
						{
							if((RunningOnWow64 && IsWow64(hProc)) || !RunningOnWow64)
							{
								// before call the DumpRegionProc, we update the iGlobalPid variable
								iGlobalPid = iPid;

								ListView_GetItemText(hList, item, PATH_COLUMN, szCaption, sizeof(szCaption));

								// create the Dialog to show the virtual sections of the corresponding process
								DialogBoxParam(hGlobalInstance, (LPCTSTR)SECTIONSDLG, hDlg, DumpRegionProc, 0);
							}
							else
							{
								MessageBox(hDlg, TEXT("The selected item is not a 32 bits process"), TEXT("Ups!"), MB_ICONERROR);
							}
							// close the handle of the process
							CloseHandle(hProc);
						}
						else
							MessageBox(hDlg, TEXT("Couldn't receive process handle!"), TEXT("VSD v2.0"), MB_ICONERROR);
					}
					break;

				case IDM_COPY2CLIPBOARD:
					CopyDataToClipBoard(hList, MAX_COLS);
					break;

				case IDM_SELECTALL:
					SelectAllItems(hList);
					break;

				case IDM_PATCH_PROCESS:
					item = ListView_GetNextItem(hList, -1, LVNI_SELECTED);

					if( item!= -1)
					{
						DWORD iPid = ListView_GetPidFromItem(hList, item);
						hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, iPid);
						if(hProc != NULL)
						{
							if((RunningOnWow64 && IsWow64(hProc)) || !RunningOnWow64)
							{
								// before call the DumpRegionProc, we update the iGlobalPid variable
								iGlobalPid = iPid;

								ListView_GetItemText(hList, item, PATH_COLUMN, szCaption, sizeof(szCaption));

								// create the Dialog to show the virtual sections of the corresponding process
								DialogBoxParam(hGlobalInstance, (LPCTSTR)PATCHPROCESSDLG, hDlg, PatchProcessDlgProc, 0);
							}
							else
							{
								MessageBox(hDlg, TEXT("The selected item is not a 32 bits process"), TEXT("Ups!"), MB_ICONERROR);
							}
							CloseHandle(hProc);
						}
						else
							MessageBox(hDlg, TEXT("Couldn't receive process handle!"), TEXT("VSD v2.0"), MB_ICONERROR);
					}
					break;
					
				default: break;
			}

			return 0;

		case WM_COMMAND:
			switch(wParam)
			{
				//case HOTKEY_CTRL_C:
				//	MessageBox(hDlg, TEXT("Are you sure you want to quit?"), TEXT("Exit VSD?"), MB_OK);
				//	break;

				case IDM_THREADS1:
					item = ListView_GetNextItem(hList, -1, LVNI_SELECTED); 

					if(item != -1)
					{
							
						iPid = ListView_GetPidFromItem(hList, item);

						hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, iPid);
						if(hProc != NULL)
						{
							if((RunningOnWow64 && IsWow64(hProc)) || !RunningOnWow64)
							{
								iGlobalPid = iPid;

								ListView_GetItemText(hList, item, PATH_COLUMN, szCaption, sizeof(szCaption));

								DialogBoxParam(hGlobalInstance, (LPCTSTR)THREADSDLG, hDlg, ThreadsDlgProc, 0);
							}
							else
							{
								MessageBox(hDlg, TEXT("The selected item is not a 32 bits process"), TEXT("Ups!"), MB_ICONERROR);
							}
							CloseHandle(hProc);
						}
						else
							MessageBox(hDlg, TEXT("Couldn't not receive process handle!"), TEXT("VSD v2.0"), MB_ICONERROR);
					}
					break;

				case IDM_MODULES1:
					item = ListView_GetNextItem(hList, -1, LVNI_SELECTED);
					if(item != -1)
					{
						iPid = ListView_GetPidFromItem(hList, item);
						hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, iPid);
						if(hProc != NULL)
						{
							if((RunningOnWow64 && IsWow64(hProc)) || !RunningOnWow64)
							{
								iGlobalPid = iPid;
								
								bGlobalPastePEHeader = IsDlgButtonChecked(hDlg, PASTEPEHEADER);
								bGlobalFixHeader = IsDlgButtonChecked(hDlg, FIXPEHEADER);

								//ListView_GetItemText(hList, item, IB_COLUMN, szAddr, sizeof(szAddr));
								//ListView_GetItemText(hList, item, IZ_COLUMN, szSize, sizeof(szSize));

								//RegionAddr = strtol(szAddr, 0, 16);
								//RegionSize = strtol(szSize, 0, 16);
								ListView_GetItemText(hList, item, PATH_COLUMN, szCaption, sizeof(szCaption));

								DialogBoxParam(hGlobalInstance, (LPCTSTR)MODULESDLG, hDlg, EnumModulesDlgProc, 0);
							}
							else
							{
								MessageBox(hDlg, TEXT("The selected item is not a 32 bits process"), TEXT("Ups!"), MB_ICONERROR);
							}
							CloseHandle(hProc);
						}
						else
						{
							MessageBox(hDlg, TEXT("Couldn't receive process handle!"), TEXT("VSD v2.0"), MB_ICONERROR);
						}
					}
					break;

				case IDM_HANDLES1:
					item = ListView_GetNextItem(hList, -1, LVNI_SELECTED);
					if(item != -1)
					{
						iPid = ListView_GetPidFromItem(hList, item);
						hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, iPid);
						if(hProc != NULL)
						{
							if((RunningOnWow64 && IsWow64(hProc)) || !RunningOnWow64)
							{
								iGlobalPid = iPid;

								ListView_GetItemText(hList, item, PATH_COLUMN, szCaption, sizeof(szCaption));

								DialogBoxParam(hGlobalInstance, (LPCTSTR)HANDLESDLG, hDlg, EnumHandlesDlgProc, 0);
							}
							else
							{
								MessageBox(hDlg, TEXT("The selected item is not a 32 bits process"), TEXT("Ups!"), MB_ICONERROR);
							}
							CloseHandle(hProc);
						}
						else
						{
							MessageBox(hDlg, TEXT("Couldn't receive process handle!"), TEXT("VSD v2.0"), MB_ICONERROR);
						}
					}
					break;

				case EXCLUDE_X64_PROCS:
					RefreshLV(hDlg, hList);
					break;

				case BT_REFRESH:
					RefreshLV(hDlg, hList);
					break;

				case IDM_ABOUT1:
				case BT_ABOUT:
					ShowAboutInfo(hDlg);
					break;

				case IDM_EXIT1:
				case IDCANCEL:
					if(MessageBox(hDlg, TEXT("Are you sure you want to quit?"), TEXT("Exit VSD?"), MB_YESNO) == IDYES)
					{
						// destroy opened menu handles
						DestroyMenu(hMainMenu);
						DestroyMenu(hViewSubMenu);
						DestroyMenu(hDumpSubMenu);

						// close the main dialog
						EndDialog(hDlg, 0);
					}
					break;
			}
			break;

		case WM_CLOSE:
			break;
	}

	return 0;
}

int CALLBACK ListViewRegionsCompareProc(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort)
{
	char szText[MAX_PATH], szText2[MAX_PATH];
	int retval;
	long num1, num2;

	if(lParamSort == ADDR_SORT_ASCENDING)
	{	
		ListView_GetItemText(hRegionsLV, lParam1, ADDR_COLUMN, szText, sizeof(szText));
		ListView_GetItemText(hRegionsLV, lParam2, ADDR_COLUMN, szText2, sizeof(szText2));

		num1 = strtol(szText, NULL, 16);
		num2 = strtol(szText2, NULL, 16);

		retval = num1 - num2;
	}
	else
	{
		if(lParamSort == ADDR_SORT_DESCENDING)
		{
			ListView_GetItemText(hRegionsLV, lParam1, ADDR_COLUMN, szText, sizeof(szText));
			ListView_GetItemText(hRegionsLV, lParam2, ADDR_COLUMN, szText2, sizeof(szText2));

			num1 = strtol(szText, NULL, 16);
			num2 = strtol(szText2, NULL, 16);

			retval = num2 - num1;
		}
		else
		{
			if(lParamSort == SIZE_SORT_ASCENDING)
			{
				ListView_GetItemText(hRegionsLV, lParam1, SIZE_COLUMN, szText, sizeof(szText));
				ListView_GetItemText(hRegionsLV, lParam2, SIZE_COLUMN, szText2, sizeof(szText2));

				num1 = strtol(szText, NULL, 16);
				num2 = strtol(szText2, NULL, 16);

				retval = num1 - num2;
			}
			else
			{
				if(lParamSort == SIZE_SORT_DESCENDING)
				{
					ListView_GetItemText(hRegionsLV, lParam1, SIZE_COLUMN, szText, sizeof(szText));
					ListView_GetItemText(hRegionsLV, lParam2, SIZE_COLUMN, szText2, sizeof(szText2));

					num1 = strtol(szText, NULL, 16);
					num2 = strtol(szText2, NULL, 16);

					retval = num2 - num1;
				}
				else
				{
					if(lParamSort == PROTECT_SORT_ASCENDING)
					{
						ListView_GetItemText(hRegionsLV, lParam1, PROTECT_COLUMN, szText, sizeof(szText));
						ListView_GetItemText(hRegionsLV, lParam2, PROTECT_COLUMN, szText2, sizeof(szText2));

						retval = lstrcmpi(szText, szText2);
					}
					else
					{
						if(lParamSort == PROTECT_SORT_DESCENDING)
						{
							ListView_GetItemText(hRegionsLV, lParam1, PROTECT_COLUMN, szText, sizeof(szText));
							ListView_GetItemText(hRegionsLV, lParam2, PROTECT_COLUMN, szText2, sizeof(szText2));

							retval = lstrcmpi(szText2, szText);
						}
						else
						{
							if(lParamSort == STATE_SORT_ASCENDING)
							{
								ListView_GetItemText(hRegionsLV, lParam1, STATE_COLUMN, szText, sizeof(szText));
								ListView_GetItemText(hRegionsLV, lParam2, STATE_COLUMN, szText2, sizeof(szText2));

								retval = lstrcmpi(szText, szText2);
							}
							else
							{
								if(lParamSort == STATE_SORT_DESCENDING)
								{
									ListView_GetItemText(hRegionsLV, lParam1, STATE_COLUMN, szText, sizeof(szText));
									ListView_GetItemText(hRegionsLV, lParam2, STATE_COLUMN, szText2, sizeof(szText2));

									retval = lstrcmpi(szText2, szText);
								}
								else
								{
									if(lParamSort == TYPE_SORT_ASCENDING)
									{
										ListView_GetItemText(hRegionsLV, lParam1, TYPE_COLUMN, szText, sizeof(szText));
										ListView_GetItemText(hRegionsLV, lParam2, TYPE_COLUMN, szText2, sizeof(szText2));

										retval = lstrcmpi(szText, szText2);
									}
									else
									{
										if(lParamSort == TYPE_SORT_DESCENDING)
										{
											ListView_GetItemText(hRegionsLV, lParam1, TYPE_COLUMN, szText, sizeof(szText));
											ListView_GetItemText(hRegionsLV, lParam2, TYPE_COLUMN, szText2, sizeof(szText2));

											retval = lstrcmpi(szText2, szText);
										}
									}

								}
							}
						}
					}
				}
			}
		}
	}

	return retval;
}

void SortRegionsListView(HWND MyhList, int iSubItem)
{
	if(iSubItem == ADDR_COLUMN)
	{
		if ((AddrSortOrder == NO_SORT) || (AddrSortOrder == ADDR_SORT_DESCENDING))
		{
			ListView_SortItems(MyhList, ListViewRegionsCompareProc, ADDR_SORT_ASCENDING);
			UpdatelParam(MyhList);
			AddrSortOrder = ADDR_SORT_ASCENDING;
		}
		else
		{
			ListView_SortItems(MyhList, ListViewRegionsCompareProc, ADDR_SORT_DESCENDING);
			UpdatelParam(MyhList);
			AddrSortOrder = ADDR_SORT_DESCENDING;
		}
	}
	else
	{
		if(iSubItem == SIZE_COLUMN)
		{
			if((SizeSortOrder == NO_SORT) || (SizeSortOrder == SIZE_SORT_DESCENDING))
			{
				ListView_SortItems(MyhList, ListViewRegionsCompareProc, SIZE_SORT_ASCENDING);
				UpdatelParam(MyhList);
				SizeSortOrder = SIZE_SORT_ASCENDING;
			}
			else
			{
				ListView_SortItems(MyhList, ListViewRegionsCompareProc, SIZE_SORT_DESCENDING);
				UpdatelParam(MyhList);
				SizeSortOrder = SIZE_SORT_DESCENDING;
			}
		}
		else
		{
			if(iSubItem == PROTECT_COLUMN)
			{
				if((ProtectSortOrder == NO_SORT) || (ProtectSortOrder == PROTECT_SORT_DESCENDING))
				{
					ListView_SortItems(MyhList, ListViewRegionsCompareProc, PROTECT_SORT_ASCENDING);
					UpdatelParam(MyhList);
					ProtectSortOrder = PROTECT_SORT_ASCENDING;
				}
				else
				{
					ListView_SortItems(MyhList, ListViewRegionsCompareProc, PROTECT_SORT_DESCENDING);
					UpdatelParam(MyhList);
					ProtectSortOrder = PROTECT_SORT_DESCENDING;
				}
			}
			else
			{
				if(iSubItem == STATE_COLUMN)
				{
					if((StateSortOrder == NO_SORT) || (StateSortOrder == STATE_SORT_DESCENDING))
					{
						ListView_SortItems(MyhList, ListViewRegionsCompareProc, STATE_SORT_ASCENDING);
						UpdatelParam(MyhList);
						StateSortOrder = STATE_SORT_ASCENDING;
					}
					else
					{
						ListView_SortItems(MyhList, ListViewRegionsCompareProc, STATE_SORT_DESCENDING);
						UpdatelParam(MyhList);
						StateSortOrder = STATE_SORT_DESCENDING;
					}
				}
				else
				{
					if(iSubItem == TYPE_COLUMN)
					{
						if((TypeSortOrder == NO_SORT) || (TypeSortOrder == TYPE_SORT_DESCENDING))
						{
							ListView_SortItems(MyhList, ListViewRegionsCompareProc, TYPE_SORT_ASCENDING);
							UpdatelParam(MyhList);
							TypeSortOrder = TYPE_SORT_ASCENDING;
						}
						else
						{
							ListView_SortItems(MyhList, ListViewRegionsCompareProc, TYPE_SORT_DESCENDING);
							UpdatelParam(MyhList);
							TypeSortOrder = TYPE_SORT_DESCENDING;
						}
					}
				}
			}
		}
	}
}

void CreateColumnsModulesLV(HWND MyhList)
{
	int index;
	LVCOLUMN lvCol = {0};
	char* lvColTitles[] = {"Name", "ImageBase", "ImageSize"};
	char szFmtText[MAX_PATH];

	for(index = 0; index < 3; index++)
	{
		lvCol.mask = LVCF_TEXT | LVCF_SUBITEM | LVCF_WIDTH | LVCF_IDEALWIDTH;
		lvCol.pszText = lvColTitles[index];

		if(index)
			lvCol.cx = lvCol.cxIdeal = 150;
		else
			lvCol.cx = lvCol.cxIdeal = 250;

		lvCol.cchTextMax = strlen(lvColTitles[index]);

		if(ListView_InsertColumn(MyhList, index, &lvCol) == -1)
		{
			sprintf_s(szFmtText, sizeof(szFmtText), "Couldn't insert column %d", index);
			MessageBox(MyGetWindowOwner(MyhList), szFmtText, TEXT("Ups!"), MB_ICONERROR);
		}
	}
}

HWND PopulateModulesLV(HWND hDlg)
{
	HWND hMyList;

	hMyList = GetDlgItem(hDlg, MODULESLV);

	if(hMyList)
	{
		/*
			ComCtl32.dll version 6 has problems with LVS_EX_GRIDLINES when its scrolled vertically.
			An option to avoid this issue is to disable the LVS_EX_GRIDLINES style.
			Another option is to disable the Windows XP Style.

			* http://stackoverflow.com/questions/1416793/listview-gridlines-issue
			* http://www.ureader.com/msg/1484143.aspx
		*/
		ListView_SetExtendedListViewStyle(hMyList, LVS_EX_GRIDLINES | LVS_EX_FULLROWSELECT | LVS_SORTASCENDING);
		
		CreateColumnsModulesLV(hMyList);
		MyEnumProcessModules(hDlg, hMyList);
	}

	return hMyList;
}

int MyEnumProcessModules(HWND hDlg, HWND MyhList)
{
	HANDLE hProc;
	HMODULE hMods[MAX_MODULES];
	DWORD cbNeeded;
	LVITEM lvItem;
	MODULEINFO ModInfo;
	char szText[MAX_PATH], procName[MAX_PATH];
	unsigned int i;

	hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, iGlobalPid);
	if(hProc != NULL)
	{
		if(EnumProcessModules(hProc, hMods, sizeof(hMods), &cbNeeded))
		{
			for(i = 0; i < (cbNeeded/sizeof(DWORD)); i++)
			{
				if(GetModuleInformation(hProc, hMods[i], &ModInfo, sizeof(ModInfo)))
				{
					memset(&lvItem, 0, sizeof(lvItem));

					lvItem.mask = LVIF_TEXT | LVIF_PARAM;
					lvItem.cchTextMax = MAX_PATH;
					lvItem.iItem = lvItem.lParam = i;
					lvItem.iSubItem = 0;

					if(ListView_InsertItem(MyhList, &lvItem) != -1)
					{				
						GetModuleFileNameEx(hProc, hMods[i], procName, sizeof(procName)/sizeof(char));

						lowercase(procName);

						ListView_SetItemText(MyhList, i, MODULE_NAME_COL, procName);

						sprintf_s(szText, sizeof(szText), "%08X", ModInfo.lpBaseOfDll);
						ListView_SetItemText(MyhList, i, MODULE_IMAGEBASE_COL, szText);

						sprintf_s(szText, sizeof(szText), "%08X", ModInfo.SizeOfImage);
						ListView_SetItemText(MyhList, i, MODULE_IMAGESIZE_COL, szText);
					}
					else
					{
						MessageBox(NULL, TEXT("Couldn't insert item!"), TEXT("Ups!"), MB_ICONERROR);
					}
				}
			}
		}
		CloseHandle(hProc);
	}

	sprintf_s(szText, sizeof(szText), "Total modules: %d", (cbNeeded/sizeof(DWORD)));
	SetDlgItemText(hDlg, TOTAL_MODULES, szText);

	return RTN_OK;
}

void SortModulesListView(HWND MyhList, int iSubItem)
{
	switch(iSubItem)
	{
		case MODULE_NAME_COL:
			if ((ModuleNameSortOrder == NO_SORT) || (ModuleNameSortOrder == MODULE_NAME_COL_SORT_DESCENDING))
			{
				ListView_SortItems(MyhList, ModulesCompareProc, MODULE_NAME_COL_SORT_ASCENDING);
				UpdatelParam(MyhList);
				ModuleNameSortOrder = MODULE_NAME_COL_SORT_ASCENDING;
			}
			else
			{
				ListView_SortItems(MyhList, ModulesCompareProc, MODULE_NAME_COL_SORT_DESCENDING);
				UpdatelParam(MyhList);
				ModuleNameSortOrder = MODULE_NAME_COL_SORT_DESCENDING;
			}
			break;

		case MODULE_IMAGEBASE_COL:
			if ((ModuleImageBaseSortOrder == NO_SORT) || (ModuleImageBaseSortOrder == MODULE_IMAGEBASE_COL_SORT_DESCENDING))
			{
				ListView_SortItems(MyhList, ModulesCompareProc, MODULE_IMAGEBASE_COL_SORT_ASCENDING);
				UpdatelParam(MyhList);
				ModuleImageBaseSortOrder = MODULE_IMAGEBASE_COL_SORT_ASCENDING;
			}
			else
			{
				ListView_SortItems(MyhList, ModulesCompareProc, MODULE_IMAGEBASE_COL_SORT_DESCENDING);
				UpdatelParam(MyhList);
				ModuleImageBaseSortOrder = MODULE_IMAGEBASE_COL_SORT_DESCENDING;
			}
			break;

		case MODULE_IMAGESIZE_COL:
			if ((ModuleImageSizeSortOrder == NO_SORT) || (ModuleImageSizeSortOrder == MODULE_IMAGESIZE_COL_SORT_DESCENDING))
			{
				ListView_SortItems(MyhList, ModulesCompareProc, MODULE_IMAGESIZE_COL_SORT_ASCENDING);
				UpdatelParam(MyhList);
				ModuleImageSizeSortOrder = MODULE_IMAGESIZE_COL_SORT_ASCENDING;
			}
			else
			{
				ListView_SortItems(MyhList, ModulesCompareProc, MODULE_IMAGESIZE_COL_SORT_DESCENDING);
				UpdatelParam(MyhList);
				ModuleImageSizeSortOrder = MODULE_IMAGESIZE_COL_SORT_DESCENDING;
			}
			break;

		default: break;
	}
}

BOOL CALLBACK EnumModulesDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	HANDLE hProc;
	int SelItem, retval;
	char szAddr[9], szSize[9], ModuleName[MAX_PATH];

	switch(uMsg)
	{
		case WM_INITDIALOG:
			SetClassLongPtr(hDlg, GCLP_HICON, (long)LoadIcon(0, IDI_INFORMATION));

			sprintf_s(ModuleName, sizeof(ModuleName), "Loaded Modules - [Process: %s - PID: %d]", szCaption, iGlobalPid);
			SetWindowText(hDlg, ModuleName);

			hModulesCopy2Clip = CreatePopupMenu();
			AppendMenu(hModulesCopy2Clip, MF_STRING, IDM_SELECTALL, TEXT("&Select All"));
			AppendMenu(hModulesCopy2Clip, MF_STRING, IDM_COPY2CLIPBOARD, TEXT("&Copy to Clipboard"));

			InsertMenu(hModulesCopy2Clip, 2, MF_SEPARATOR, 0, "-");

			hDumpModuleSubMenu = CreatePopupMenu();
			InsertMenu(hModulesCopy2Clip, 2, MF_POPUP, (UINT)hDumpModuleSubMenu, TEXT("&Dump"));
			AppendMenu(hDumpModuleSubMenu, MF_STRING, IDM_DUMP_FULL, TEXT("&Full"));
			AppendMenu(hDumpModuleSubMenu, MF_STRING, IDM_DUMP_PARTIAL, TEXT("&Partial"));

			hModulesLV = PopulateModulesLV(hDlg);

			return 1;

		case WM_NOTIFY:
			switch(LOWORD(wParam))
			{
				case MODULESLV:
					switch(((LPNMHDR)lParam)->code)
					{
						case LVN_COLUMNCLICK:
							{
								NMLISTVIEW* pListView = (NMLISTVIEW*)lParam;
								SortModulesListView(hModulesLV, pListView->iSubItem);
							}
							break;
						default: break;
					}
				default: break;
			}
			return 0;

		case WM_CONTEXTMENU:
			GetCursorPos(&pt2);
			SelItem = TrackPopupMenuEx(hModulesCopy2Clip, TPM_RETURNCMD, pt2.x, pt2.y, hDlg, NULL);

			switch(SelItem)
			{
				case IDM_COPY2CLIPBOARD:
					CopyDataToClipBoard(hModulesLV, 3);
					break;

				case IDM_SELECTALL:
					SelectAllItems(hModulesLV);
					break;

				case IDM_DUMP_FULL:
					item = ListView_GetNextItem(hModulesLV, -1, LVNI_SELECTED);
										
					if( item != -1)
					{
						hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, iGlobalPid);
						if(hProc != NULL)
						{
							if((RunningOnWow64 && IsWow64(hProc)) || !RunningOnWow64)
							{
								ListView_GetItemText(hModulesLV, item, MODULE_IMAGEBASE_COL, szAddr, sizeof(szAddr));
								ListView_GetItemText(hModulesLV, item, MODULE_IMAGESIZE_COL, szSize, sizeof(szSize));
								ListView_GetItemText(hModulesLV, item, MODULE_NAME_COL, ModuleName, sizeof(ModuleName));

								retval = MyDumpModuleFunction((void*)strtol(szAddr, NULL, 16), strtol(szSize, NULL, 16), ModuleName, DUMPFULL, bGlobalPastePEHeader, bGlobalFixHeader,  hDlg);

								ValidateResult(retval);
							}
							else
							{
								MessageBox(hDlg, TEXT("The selected item is not a 32 bits process"), TEXT("Ups!"), MB_ICONERROR);
							}
							CloseHandle(hProc);
						}
						else
							MessageBox(hDlg, TEXT("Couldn't receive process handle!"), TEXT("VSD v2.0"), MB_ICONERROR);
					}
					break;
				
				case IDM_DUMP_PARTIAL:
					item = ListView_GetNextItem(hModulesLV, -1, LVNI_SELECTED);
										
					if( item != -1)
					{
						hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, iGlobalPid);
						if(hProc != NULL)
						{
							if((RunningOnWow64 && IsWow64(hProc)) || !RunningOnWow64)
							{
								ListView_GetItemText(hModulesLV, item, MODULE_IMAGEBASE_COL, szAddr, sizeof(szAddr));
								ListView_GetItemText(hModulesLV, item, MODULE_IMAGESIZE_COL, szSize, sizeof(szSize));
								ListView_GetItemText(hModulesLV, item, MODULE_NAME_COL, szGlobalModuleName, sizeof(szGlobalModuleName));

								RegionAddr = strtol(szAddr, 0, 16);
								RegionSize = strtol(szSize, 0, 16);

								DumpingModule = TRUE;

								ListView_GetItemText(hModulesLV, item, MODULE_NAME_COL, szCaption, sizeof(szCaption));

								DialogBoxParam(hGlobalInstance, (LPCTSTR)PARTIALDUMP, hDlg, PartialDumpProc, 0);
							}
							else
							{
								MessageBox(hDlg, TEXT("The selected item is not a 32 bits process"), TEXT("Ups!"), MB_ICONERROR);
							}
							CloseHandle(hProc);
						}
						else
							MessageBox(hDlg, TEXT("Couldn't receive process handle!"), TEXT("VSD v2.0"), MB_ICONERROR);
					}
					break;

				default: break;
			}

			return 0;

		case WM_COMMAND:
			switch(wParam)
			{
				case IDOK:
				case IDCANCEL:
					EndDialog(hDlg, 0);
			}
	}
	return 0;
}

void SortHandlesListView(HWND MyhList, int iSubItem)
{
	switch(iSubItem)
	{
		case HANDLE_TYPE_COL:
			if ((HandleTypeSortOrder == NO_SORT) || (HandleTypeSortOrder == HANDLE_TYPE_COL_SORT_DESCENDING))
			{
				ListView_SortItems(MyhList, HandlesCompareProc, HANDLE_TYPE_COL_SORT_ASCENDING);
				UpdatelParam(MyhList);
				HandleTypeSortOrder = HANDLE_TYPE_COL_SORT_ASCENDING;
			}
			else
			{
				ListView_SortItems(MyhList, HandlesCompareProc, HANDLE_TYPE_COL_SORT_DESCENDING);
				UpdatelParam(MyhList);
				HandleTypeSortOrder = HANDLE_TYPE_COL_SORT_DESCENDING;
			}
			break;

		case HANDLE_NAME_COL:
			if ((HandleNameSortOrder == NO_SORT) || (HandleNameSortOrder == HANDLE_NAME_COL_SORT_DESCENDING))
			{
				ListView_SortItems(MyhList, HandlesCompareProc, HANDLE_NAME_COL_SORT_ASCENDING);
				UpdatelParam(MyhList);
				HandleNameSortOrder = HANDLE_NAME_COL_SORT_ASCENDING;
			}
			else
			{
				ListView_SortItems(MyhList, HandlesCompareProc, HANDLE_NAME_COL_SORT_DESCENDING);
				UpdatelParam(MyhList);
				HandleNameSortOrder = HANDLE_NAME_COL_SORT_DESCENDING;
			}
			break;
		
		case HANDLE_COL:
			if ((HandleSortOrder == NO_SORT) || (HandleSortOrder == HANDLE_COL_SORT_DESCENDING))
			{
				ListView_SortItems(MyhList, HandlesCompareProc, HANDLE_COL_SORT_ASCENDING);
				UpdatelParam(MyhList);
				HandleSortOrder = HANDLE_COL_SORT_ASCENDING;
			}
			else
			{
				ListView_SortItems(MyhList, HandlesCompareProc, HANDLE_COL_SORT_DESCENDING);
				UpdatelParam(MyhList);
				HandleSortOrder = HANDLE_COL_SORT_DESCENDING;
			}
			break;

		default: break;
	}
}

BOOL CALLBACK EnumHandlesDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	DWORD SetItem;
	char szText[MAX_PATH];

	switch(uMsg)
	{
		case WM_INITDIALOG:
			SetClassLongPtr(hDlg, GCLP_HICON, (long)LoadIcon(0, IDI_INFORMATION));

			sprintf_s(szText, sizeof(szText), "Handles - [Process: %s - PID: %d]", szCaption, iGlobalPid);
			SetWindowText(hDlg, szText);

			hHandlesCopy2Clip = CreatePopupMenu();
			AppendMenu(hHandlesCopy2Clip, MF_STRING, IDM_SELECTALL, TEXT("&Select All"));
			AppendMenu(hHandlesCopy2Clip, MF_STRING, IDM_COPY2CLIPBOARD, TEXT("&Copy to Clipboard"));

			hHandlesLV = PopulateHandlesLV(hDlg);

			return 1;

		case WM_NOTIFY:
			switch(LOWORD(wParam))
			{
				case HANDLESLV:
					switch(((LPNMHDR)lParam)->code)
					{
						case LVN_COLUMNCLICK:
							{
								NMLISTVIEW* pListView = (NMLISTVIEW*)lParam;
								SortHandlesListView(hHandlesLV, pListView->iSubItem);
							}
							break;
						default: break;
					}
				default: break;
			}
			return 0;

		case WM_CONTEXTMENU:
			GetCursorPos(&pt2);
			SetItem = TrackPopupMenuEx(hHandlesCopy2Clip, TPM_RETURNCMD, pt2.x, pt2.y, hDlg, NULL);

			switch(SetItem)
			{
				case IDM_COPY2CLIPBOARD:
					CopyDataToClipBoard(hHandlesLV, 2);
					break;

				case IDM_SELECTALL:
					SelectAllItems(hHandlesLV);
					break;

				default: break;
			}

			return 0;

		case WM_COMMAND:
			switch(wParam)
			{
				case IDCANCEL:
				case IDOK:
					EndDialog(hDlg, 0);
			}
	}
	return 0;
}

PVOID GetLibraryProcAddress(PSTR LibraryName, PSTR ProcName)
{
    return GetProcAddress(GetModuleHandleA(LibraryName), ProcName);
}

BOOL CALLBACK DumpRegionProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	DWORD SetItem;
	int iPos, retval, iPerPage, CurPos, iTop, lastItem;
	HWND hAddrEdit, hSizeEdit;
	char Address[9], Size[9], szText[MAX_PATH];

	switch (uMsg)
	{
		case WM_NOTIFY:
			switch(LOWORD(wParam))
			{
				case LV_REGIONS:
					switch(((LPNMHDR)lParam)->code)
					{
						case LVN_COLUMNCLICK:
							{
								NMLISTVIEW* pListView = (NMLISTVIEW*)lParam;
								SortRegionsListView(hRegionsLV, pListView->iSubItem);
							}
							break;
						
						case NM_CLICK:
							iPos = ListView_GetNextItem(hRegionsLV, -1, LVNI_SELECTED);
							if(iPos != -1)
								SetAddrAndSizeEdits(hDlg, hRegionsLV, iPos);
							break;
						
						case LVN_KEYDOWN:
							{
								switch(((LPNMLVKEYDOWN)lParam)->wVKey)
								{
									case VK_HOME:
										SetAddrAndSizeEdits(hDlg, hRegionsLV, 0);
										break;

									case VK_END:
										SetAddrAndSizeEdits(hDlg, hRegionsLV, ListView_GetItemCount(hRegionsLV) - 1);
										break;

									case VK_PRIOR:
										CurPos = ListView_GetNextItem(hRegionsLV, -1, LVNI_FOCUSED);
										iPerPage = ListView_GetCountPerPage(hRegionsLV);
										iTop = ListView_GetTopIndex(hRegionsLV);

										if(iTop == CurPos)
										{
											iPos = iTop - iPerPage + 1;
											if(iPos < 0)
											{
												iPos = 0;
											}
										}
										else
										{
											iPos = iTop;
										}

										SetAddrAndSizeEdits(hDlg, hRegionsLV, iPos);
										break;

									case VK_NEXT:
										CurPos = ListView_GetNextItem(hRegionsLV, -1, LVNI_FOCUSED);
										iPerPage = ListView_GetCountPerPage(hRegionsLV);
										iTop = ListView_GetTopIndex(hRegionsLV);
										
										lastItem = iTop + iPerPage - 1;
										
										if(CurPos < lastItem)
										{
											iPos = lastItem;
										}
										else
										{
											iPos = CurPos + iPerPage - 1;
											if(iPos >= ListView_GetItemCount(hRegionsLV))
											{
												iPos = ListView_GetItemCount(hRegionsLV) - 1;
											}
										}

										SetAddrAndSizeEdits(hDlg, hRegionsLV, iPos);
										break;

									case VK_UP:
										iPos = ListView_GetNextItem(hRegionsLV, -1, LVNI_FOCUSED);
										if(iPos != -1)
										{
											iPos--;
											if(iPos < 0)
												iPos = 0;

											SetAddrAndSizeEdits(hDlg, hRegionsLV, iPos);
										}
										break;

									case VK_DOWN:
										iPos = ListView_GetNextItem(hRegionsLV, -1, LVNI_FOCUSED);
										if(iPos != -1)
										{
											if(iPos >= ListView_GetItemCount(hRegionsLV) - 1)
												iPos = ListView_GetItemCount(hRegionsLV) - 1;
											else
												iPos++;

											SetAddrAndSizeEdits(hDlg, hRegionsLV, iPos);
										}
										break;

									default: break;
								}
							}
							break;

						default: break;
					}
					break;

				default: break;
			}
			return 0;

		case WM_INITDIALOG:
			SetClassLongPtr(hDlg, GCLP_HICON, (long)LoadIcon(0, IDI_INFORMATION));

			// set the new window caption
			sprintf_s(szText, sizeof(szText), "Region Dump Information - [Process: %s - PID: %d]", szCaption, iGlobalPid);
			SetWindowText(hDlg, szText);

			// get handles for editboxes controls
			hAddrEdit = GetDlgItem(hDlg, ADDRESS_EDIT);
			hSizeEdit = GetDlgItem(hDlg, SIZE_EDIT);

			Edit_LimitText(hAddrEdit, 8);
			Edit_LimitText(hSizeEdit, 8);

			hCopy2Clip = CreatePopupMenu();
			AppendMenu(hCopy2Clip, MF_STRING, IDM_SELECTALL, TEXT("&Select All"));
			AppendMenu(hCopy2Clip, MF_STRING, IDM_COPY2CLIPBOARD, TEXT("&Copy to Clipboard"));

			hRegionsLV = PopulateRegionLV(hDlg);

			SetAddrAndSizeEdits(hDlg, hRegionsLV, 0);

			return 1;

		case WM_CONTEXTMENU:
			GetCursorPos(&pt2);
			SetItem = TrackPopupMenuEx(hCopy2Clip, TPM_RETURNCMD, pt2.x, pt2.y, hDlg, NULL);

			switch(SetItem)
			{
				case IDM_COPY2CLIPBOARD:
					CopyDataToClipBoard(hRegionsLV, MAX_COLSREG);
					break;

				case IDM_SELECTALL:
					SelectAllItems(hRegionsLV);
					break;

				default: break;
			}

			return 0;

		case WM_COMMAND:
			switch(LOWORD(wParam))
			{
				//case HOTKEY_CTRL_C:
				//	MessageBox(hDlg, TEXT("Ctrl+C pressed!"), TEXT("HOTKEY!"), MB_ICONERROR);
				//	return 0;

				case DUMP_REGION:
					if(GetDlgItemText(hDlg, ADDRESS_EDIT,  Address, 9))
					{
						if(IsValidHexString(Address))
						{
							if(GetDlgItemText(hDlg, SIZE_EDIT, Size, 9))
							{
								if(IsValidHexString(Size))
								{
									retval = DumpMemoryRegion((void*)strtol(Address, NULL, 16), strtol(Size, NULL, 16), DUMPREGION, FALSE, FALSE, hDlg);
									ValidateResult(retval);
								}
								else
								{
									MessageBox(hDlg, TEXT("The value entered as Size is not a valid hex number"), TEXT("Ups!"), MB_ICONERROR);
								}
							}
							else
							{
								MessageBox(hDlg, TEXT("You didn't enter the Size"), TEXT("Are you kidding?"), MB_ICONERROR);
							}
						}
						else
						{
							MessageBox(hDlg, TEXT("The value entered as Address is not a valid hex number"), TEXT("Ups!"), MB_ICONERROR);
						}
					}
					else
					{
						MessageBox(hDlg, TEXT("You didn't enter an Address"), "Are you kidding?", MB_ICONERROR);
					}
					break;

				case BT_REFRESH:
					ListView_DeleteAllItems(hRegionsLV);
					EnumRegions(hRegionsLV);
					break;

				case BT_CLOSE:
					DestroyMenu(hCopy2Clip);
					EndDialog(hDlg, 0);
					break;

				case IDCANCEL:
					DestroyMenu(hCopy2Clip);
					EndDialog(hDlg, 0);
					break;

				default: break;
			}
			break;

		case WM_CLOSE:
			DestroyMenu(hCopy2Clip);
			EndDialog(hDlg, 0);
	}

	return 0;
}

HWND MyGetWindowOwner(HWND MyhList)
{
	return GetWindow(MyhList, GW_OWNER);
}

void InitCommonCtrlsEx(void)
{
	INITCOMMONCONTROLSEX icex;

	icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
	icex.dwICC = ICC_LISTVIEW_CLASSES;
	
	InitCommonControlsEx(&icex);
}

void CreateColumns(HWND MyhList)
{
	int index;
	LVCOLUMN lvCol = {0};
	char* lvColTitles[] = {"Path", "PID", "ImageBase", "ImageSize"};
	char szFmtText[MAX_PATH];

	for(index = 0; index < MAX_COLS; index++)
	{
		lvCol.mask = LVCF_TEXT | LVCF_SUBITEM | LVCF_WIDTH | LVCF_IDEALWIDTH;
		lvCol.pszText = lvColTitles[index];
		
		if(index != 0)
			lvCol.cx = lvCol.cxIdeal = 100;
		else
			lvCol.cx = lvCol.cxIdeal = 200;

		lvCol.cchTextMax = strlen(lvColTitles[index]);

		if(ListView_InsertColumn(MyhList, index, &lvCol) == -1)
		{
			sprintf_s(szFmtText, sizeof(szFmtText), "Couldn't insert column %d", index);
			MessageBox(MyGetWindowOwner(MyhList), szFmtText, TEXT("Ups!"), MB_ICONERROR);
		}
	}
}

int AdjustPrivileges(void)
{
	HANDLE hToken;

    if(!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken))
    {
        if(GetLastError() == ERROR_NO_TOKEN)
        {
            if(!ImpersonateSelf(SecurityImpersonation))
            return RTN_ERROR;

            if(!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken))
			{
                MessageBox(NULL, TEXT("OpenThreadToken error"), TEXT("Ups!"), MB_ICONERROR);
				return RTN_ERROR;
            }
         }
        else
			return RTN_ERROR;
     }

	if(!SetPrivilege(hToken, SE_DEBUG_NAME, TRUE))
	{
        CloseHandle(hToken);

        return RTN_ERROR;
    }

	return RTN_OK;
}

BOOL SetPrivilege(
    HANDLE hToken,          // token handle
    LPCTSTR Privilege,      // Privilege to enable/disable
    BOOL bEnablePrivilege   // TRUE to enable.  FALSE to disable
	)
{
    TOKEN_PRIVILEGES tp;
    LUID luid;
    TOKEN_PRIVILEGES tpPrevious;
    DWORD cbPrevious=sizeof(TOKEN_PRIVILEGES);

    if(!LookupPrivilegeValue( NULL, Privilege, &luid )) return FALSE;

    // 
    // first pass.  get current privilege setting
    // 
    tp.PrivilegeCount           = 1;
    tp.Privileges[0].Luid       = luid;
    tp.Privileges[0].Attributes = 0;

    AdjustTokenPrivileges(
            hToken,
            FALSE,
            &tp,
            sizeof(TOKEN_PRIVILEGES),
            &tpPrevious,
            &cbPrevious
            );

    if (GetLastError() != ERROR_SUCCESS) return FALSE;

    // 
    // second pass.  set privilege based on previous setting
    // 
    tpPrevious.PrivilegeCount       = 1;
    tpPrevious.Privileges[0].Luid   = luid;

    if(bEnablePrivilege) {
        tpPrevious.Privileges[0].Attributes |= (SE_PRIVILEGE_ENABLED);
    }
    else {
        tpPrevious.Privileges[0].Attributes ^= (SE_PRIVILEGE_ENABLED &
            tpPrevious.Privileges[0].Attributes);
    }

    AdjustTokenPrivileges(
            hToken,
            FALSE,
            &tpPrevious,
            cbPrevious,
            NULL,
            NULL
            );

    if (GetLastError() != ERROR_SUCCESS) return FALSE;

    return TRUE;
}

BOOL ListProcesses(HWND hDlg, HWND MyhList)
{
	LVITEM lvItem;
	DWORD br, cbNeeded;
	unsigned int proc_count, iCount = 0;
	HANDLE hProc;
	char szText[MAX_PATH], szProcessName[MAX_PATH];
	MODULEINFO modInfo;

	if(IsDlgButtonChecked(hDlg, EXCLUDE_X64_PROCS) == BST_CHECKED)
	{
		if(EnumProcesses(pIds, sizeof(pIds), &br))
		{
			for(proc_count = 0; proc_count < (br/sizeof(DWORD)); proc_count++)
			{
				// special case: process with PID 0
				hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pIds[proc_count]);
				if(hProc != NULL)
				{	
					// here, we only care about WoW64 processes
					if(IsWow64(hProc))
					{
						GetModuleFileNameEx(hProc, NULL, szProcessName, sizeof(szProcessName)/sizeof(char));

						memset(&lvItem, 0, sizeof(lvItem));

						lvItem.mask = LVIF_TEXT | LVIF_PARAM;
						lvItem.cchTextMax = MAX_PATH;
						
						lvItem.iItem = lvItem.lParam = iCount;
						lvItem.iSubItem = 0;

						lowercase(szProcessName);

						//with PathFindFileName we extract the executable name from the full path
						lvItem.pszText = PathFindFileName(szProcessName);
						
						if(ListView_InsertItem(MyhList, &lvItem) != -1)
						{
							_itoa_s(pIds[proc_count], szText, sizeof(szText), 10);
							ListView_SetItemText(MyhList, iCount, 1, szText);

							EnumProcessModules(hProc, hMods, sizeof(hMods), &cbNeeded);
							if(GetModuleInformation(hProc, hMods[0], &modInfo, sizeof(modInfo)))
							{
								sprintf_s(szText, sizeof(szText), "%08X", modInfo.lpBaseOfDll);
								ListView_SetItemText(MyhList, iCount, 2, szText);

								sprintf_s(szText, sizeof(szText), "%08X", modInfo.SizeOfImage);
								ListView_SetItemText(MyhList, iCount, 3, szText);
							}
							else
							{
								ListView_SetItemText(MyhList, iCount, 0, "System Idle Process");
								ListView_SetItemText(MyhList, iCount, 2, "00000000");
								ListView_SetItemText(MyhList, iCount, 3, "00000000");
							}
						}
						else
						{
							MessageBox(MyGetWindowOwner(MyhList), TEXT("Couldn't not insert item"), TEXT("Ups!"), MB_ICONERROR);
						}
						
						iCount++;
					}
				}
				else
				{
					memset(&lvItem, 0, sizeof(lvItem));

					lvItem.mask = LVIF_TEXT | LVIF_PARAM;
					lvItem.cchTextMax = MAX_PATH;
					
					lvItem.iItem = lvItem.lParam = iCount;
					lvItem.iSubItem = 0;

					lowercase(szProcessName);

					lvItem.pszText = TEXT("System Idle Process");

					if(ListView_InsertItem(MyhList, &lvItem) == -1)
						MessageBox(MyGetWindowOwner(MyhList), TEXT("Couldn't not insert Item"), TEXT("Ups!"), MB_ICONERROR);
					else
					{
						_itoa_s(pIds[proc_count], szText, sizeof(szText), 10);
						ListView_SetItemText(MyhList, iCount, 1, szText);

						ListView_SetItemText(MyhList, iCount, 2, "00000000");
						ListView_SetItemText(MyhList, iCount, 3, "00000000");
					}
					
					iCount++;
				}
				CloseHandle(hProc);
			}

			sprintf_s(szText, sizeof(szText), "Total number of processes: %d", iCount);
			SetDlgItemText(hDlg, NUM_PROCESSES, szText);
		}
	}
	else
	{
		if(EnumProcesses(pIds, sizeof(pIds), &br))
		{
			for(proc_count = 0; proc_count < (br/sizeof(DWORD)); proc_count++)
			{
				// special case: process with PID 0
				hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pIds[proc_count]);
				if(hProc != NULL)
				{	
					// here, we care all processes, x86 and x64
					GetModuleFileNameEx(hProc, NULL, szProcessName, sizeof(szProcessName)/sizeof(char));

					memset(&lvItem, 0, sizeof(lvItem));

					lvItem.mask = LVIF_TEXT | LVIF_PARAM;
					lvItem.cchTextMax = MAX_PATH;
					
					lvItem.iItem = lvItem.lParam = proc_count;
					lvItem.iSubItem = 0;

					lowercase(szProcessName);

					//with PathFindFileName we extract the executable name from the full path
					lvItem.pszText = PathFindFileName(szProcessName);
					
					if(ListView_InsertItem(MyhList, &lvItem) != -1)
					{
						_itoa_s(pIds[proc_count], szText, sizeof(szText), 10);
						ListView_SetItemText(MyhList, proc_count, 1, szText);

						EnumProcessModules(hProc, hMods, sizeof(hMods), &cbNeeded);
						if(GetModuleInformation(hProc, hMods[0], &modInfo, sizeof(modInfo)))
						{
							sprintf_s(szText, sizeof(szText), "%08X", modInfo.lpBaseOfDll);
							ListView_SetItemText(MyhList, proc_count, 2, szText);

							sprintf_s(szText, sizeof(szText), "%08X", modInfo.SizeOfImage);
							ListView_SetItemText(MyhList, proc_count, 3, szText);
						}
						else
						{
							ListView_SetItemText(MyhList, proc_count, 0, "System Idle Process");
							ListView_SetItemText(MyhList, proc_count, 2, "00000000");
							ListView_SetItemText(MyhList, proc_count, 3, "00000000");
						}
					}
					else
					{
						MessageBox(MyGetWindowOwner(MyhList), TEXT("Couldn't not insert item"), TEXT("Ups!"), MB_ICONERROR);
					}
				}
				else
				{
					memset(&lvItem, 0, sizeof(lvItem));

					lvItem.mask = LVIF_TEXT | LVIF_PARAM;
					lvItem.cchTextMax = MAX_PATH;
					
					lvItem.iItem = lvItem.lParam = proc_count;
					lvItem.iSubItem = 0;

					lowercase(szProcessName);

					lvItem.pszText = TEXT("System Idle Process");

					if(ListView_InsertItem(MyhList, &lvItem) == -1)
						MessageBox(MyGetWindowOwner(MyhList), TEXT("Couldn't not insert Item"), TEXT("Ups!"), MB_ICONERROR);
					else
					{
						_itoa_s(pIds[proc_count], szText, sizeof(szText), 10);
						ListView_SetItemText(MyhList, proc_count, 1, szText);

						ListView_SetItemText(MyhList, proc_count, 2, "00000000");
						ListView_SetItemText(MyhList, proc_count, 3, "00000000");
					}
				}
				CloseHandle(hProc);
			}

			// set the total number of processes in the static control
			sprintf_s(szText, sizeof(szText), "Total number of processes: %d", (br/sizeof(DWORD)));
			SetDlgItemText(hDlg, NUM_PROCESSES, szText);
		}
	}

	return FALSE;
}

HWND PopulateListView(HWND hDlg)
{
	HWND hMyList;

	hMyList = GetDlgItem(hDlg, LV_PROCESSES);

	if(hMyList)
	{
		/*
			ComCtl32.dll version 6 has problems with LVS_EX_GRIDLINES when its scrolled vertically.
			An option to avoid this issue is to disable the LVS_EX_GRIDLINES style.
			Another option is to disable the Windows XP Style.

			* http://stackoverflow.com/questions/1416793/listview-gridlines-issue
			* http://www.ureader.com/msg/1484143.aspx
		*/
		ListView_SetExtendedListViewStyle(hMyList, LVS_EX_GRIDLINES | LVS_EX_FULLROWSELECT);
		
		CreateColumns(hMyList);

		ListProcesses(hDlg, hMyList);
	}

	return hMyList;
}

DWORD GetSuspendThreadCount(HANDLE hThread)
{
	DWORD retval;
	retval = SuspendThread(hThread);
	ResumeThread(hThread);
	return retval;
}

DWORD GetResumeThreadCount(HANDLE hThread)
{
	DWORD retval;
	retval = ResumeThread(hThread);
	return retval;
}

LPVOID GetThreadTebAddress(DWORD ThreadId)
{
	/*
		Thanks to j00ru for the hint about remote teb method!.

		* TEB of the current thread: fs:[18h].
		* TEB of a remote thread: you have to: OpenThread + GetThreadContext +
		GetThreadSelectorEntry(CONTEXT.SegFs) + Translate the result of the
		function to an address + CloseThread.

		* Translate result of GetThreadSelectorEntry to an address: http://gynvael.coldwind.pl/?id=93
	*/

	HANDLE hThread;
	//DWORD BytesRead;
	LPVOID PebAddress = NULL;
	CONTEXT tContext;
	LDT_ENTRY ldtEntry;

	hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, ThreadId);
	if(hThread != NULL)
	{
		tContext.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;

		if(GetThreadContext(hThread, &tContext))
		{
			if(GetThreadSelectorEntry(hThread, tContext.SegFs, &ldtEntry))
				PebAddress = (LPVOID)(ldtEntry.BaseLow | (ldtEntry.HighWord.Bits.BaseMid << 16) | (ldtEntry.HighWord.Bits.BaseHi << 24));
		}
		CloseHandle(hThread);
	}

	return PebAddress;
}

const char* DwordToHex(DWORD value)
{
	char szText[MAX_PATH];

	sprintf_s(szText, sizeof(szText), "%08X", value);
	return szText;
}

void DebugMe(char* msgText)
{
	MessageBox(NULL, msgText, TEXT("Debug message"), MB_OK);
}

void DebugShowDword(unsigned long dword)
{
	char szText[MAX_PATH];

	sprintf_s(szText, sizeof(szText), "Value: %08X", dword);
	MessageBox(NULL, szText, TEXT("Debug message"), MB_OK);
}