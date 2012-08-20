/*
$Id: vsd.h 12 2012-02-25 01:02:36Z crackinglandia $

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

#include "vsd_hdrs.h"

// function definitions
void ValidateResult(int retval)
{
	if(retval == OPENPROCESS_ERROR)
	{
		MessageBox(NULL, TEXT("Couldn't open process"), TEXT("Ups!"), MB_ICONERROR);
	}
	else
	{
		if(retval == VIRTULALLOC_ERROR)
		{
			MessageBox(NULL, TEXT("Coulnd't allocate memory"), TEXT("Ups!"), MB_ICONERROR);
		}
		else
		{
			if(retval == READPROCESSMEMORY_ERROR)
			{
				MessageBox(NULL, TEXT("Couldn't read memory"), TEXT("Ups!"), MB_ICONERROR);
			}
			else
			{
				if(retval == WRITEFILE_ERROR)
				{
					MessageBox(NULL, TEXT("Couldn't write file"), TEXT("Ups!"), MB_ICONERROR);
				}
				else
				{
					if(retval == RTN_OK)
					{
						MessageBox(NULL, TEXT("File successfully created!"), TEXT("Yeah!"), MB_ICONINFORMATION);
					}
					else
					{
						if(retval == RTN_ERROR)
						{
							MessageBox(NULL, TEXT("Error during operation!"), TEXT("Ups!"), MB_ICONINFORMATION);
						}
					}
				}
			}
		}
	}
}

BOOL CALLBACK PartialDumpProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	HWND hAddrEdit, hSizeEdit;
	HANDLE hProc = INVALID_HANDLE_VALUE;
	DWORD cbNeeded;
	MODULEINFO ModInfo;
	char szText[MAX_PATH];

	switch(uMsg)
	{
		case WM_INITDIALOG:
			// get the edits handles
			hAddrEdit = GetDlgItem(hDlg, DPADDRESSEDIT);
			hSizeEdit = GetDlgItem(hDlg, DPSIZEEDIT);

			// set a maximum of chars to enter
			Edit_LimitText(hAddrEdit, 16);
			Edit_LimitText(hSizeEdit, 16);

			// test if the selected process is still active
			hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, iGlobalPid);
			if(hProc != NULL)
			{
				EnumProcessModules(hProc, hMods, sizeof(hMods), &cbNeeded);
				GetModuleInformation(hProc, hMods[0], &ModInfo, sizeof(ModInfo));

				RegionAddr = (ULONGLONG)ModInfo.lpBaseOfDll;
				RegionSize = ModInfo.SizeOfImage;

				sprintf_s(szText, sizeof(szText), "%0llX", RegionAddr);
				Edit_SetText(hAddrEdit, szText);

				sprintf_s(szText, sizeof(szText), "%0llX", RegionSize);
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

							if(Edit_GetText(hAddrEdit, szText, 17))
							{
								if(IsValidHexString(szText))
								{
									RegionAddr = _strtoi64(szText, NULL, 16);

									if(Edit_GetText(hSizeEdit, szText, 17))
									{
										if(IsValidHexString(szText))
										{
											RegionSize = _strtoi64(szText, NULL, 16);

											int retval = DumpMemoryRegion((void*)RegionAddr, RegionSize, DUMPPARTIAL, FALSE, FALSE, hDlg);

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

BOOL FixHeader(HANDLE hProc, ULONGLONG ImageBase, char* szFile)
{
	HANDLE hFile;
	unsigned int iSection;
	PIMAGE_DOS_HEADER DOSHeader;
	PIMAGE_NT_HEADERS32 NTHeaders;
	PIMAGE_NT_HEADERS64 NTHeaders64;
	PIMAGE_SECTION_HEADER SectionHeader;
	PIMAGE_SECTION_HEADER OnFileSectionHeader;
	LPVOID RemoteSectionHeaderAddrs, ReadBuffer;
	DWORD nSections, BytesRead, FileSize;
	SIZE_T SectionHeaderSize;
	SIZE_T BytesWritten;
	char szText[MAX_PATH];

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
				NTHeaders64 = (PIMAGE_NT_HEADERS64)((ULONG)DOSHeader + DOSHeader->e_lfanew);

				nSections = NTHeaders->FileHeader.NumberOfSections;

				//sprintf_s(szText, sizeof(szText), "%08x", nSections);
				//MessageBox(NULL, szText, "Number of Sections", MB_OK);

				if(NTHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
				{
					SectionHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)NTHeaders + NTHeaders->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER));

					// calculate the beginning of the section header in memory
					RemoteSectionHeaderAddrs = (LPVOID)((ULONG_PTR)NTHeaders + NTHeaders->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER));

					// calculate the section header size
					SectionHeaderSize = nSections * sizeof(IMAGE_SECTION_HEADER);

					DOSHeader = (PIMAGE_DOS_HEADER)ReadBuffer;
					NTHeaders = (PIMAGE_NT_HEADERS32)((ULONG)DOSHeader + DOSHeader->e_lfanew);
					OnFileSectionHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)NTHeaders + NTHeaders->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER));
				}
				else
				{
					SectionHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)NTHeaders64 + NTHeaders64->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER));

					// calculate the beginning of the section header in memory
					RemoteSectionHeaderAddrs = (LPVOID)((ULONG_PTR)NTHeaders64 + NTHeaders64->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER));

					// calculate the section header size
					SectionHeaderSize = nSections * sizeof(IMAGE_SECTION_HEADER);

					DOSHeader = (PIMAGE_DOS_HEADER)ReadBuffer;
					NTHeaders64 = (PIMAGE_NT_HEADERS64)((ULONG)DOSHeader + DOSHeader->e_lfanew);
					OnFileSectionHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)NTHeaders64 + NTHeaders64->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER));
				}

				for(iSection = 0; iSection < nSections; iSection++)
				{

					SectionHeader->PointerToRawData = OnFileSectionHeader->VirtualAddress;
					SectionHeader->PointerToRelocations = OnFileSectionHeader->SizeOfRawData;

					SectionHeader->VirtualAddress = SectionHeader->PointerToRawData;
					SectionHeader->SizeOfRawData = SectionHeader->PointerToRelocations;

					// ----------------------------------------------------------------------
					//sprintf_s(szText, sizeof(szText), "%08x", SectionHeader->VirtualAddress);
					//MessageBox(NULL, szText, "Virtual Address", MB_OK);

					//sprintf_s(szText, sizeof(szText), "%08x", SectionHeader->PointerToRawData);
					//MessageBox(NULL, szText, "Pointer to Raw Data", MB_OK);

					//sprintf_s(szText, sizeof(szText), "%08x", SectionHeader->SizeOfRawData);
					//MessageBox(NULL, szText, "Size of Raw Data", MB_OK);

					//sprintf_s(szText, sizeof(szText), "%08x", SectionHeader->PointerToRelocations);
					//MessageBox(NULL, szText, "Pointer to Relocations", MB_OK);
					// ----------------------------------------------------------------------

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

BOOL PastePEHeader(HANDLE hProc, ULONGLONG ImageBase, char* szFile)
{
	HANDLE hFile;
	DWORD FileSize, PEHeaderSize, OldProtect;
	PIMAGE_DOS_HEADER DOSHeader;
	PIMAGE_NT_HEADERS32 PEHeader32;
	LPVOID ReadBuffer, ReadBuffer2;
	SIZE_T BytesWritten;
	DWORD BytesRead;

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
				if(PEHeader32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
					PEHeaderSize = DOSHeader->e_lfanew + sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS32);
				else
					PEHeaderSize = DOSHeader->e_lfanew + sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64);

				// frees the allocated buffer
				//VirtualFree(ReadBuffer, 0, MEM_RELEASE);

				// set the file pointer to the beginning of the PE header
				SetFilePointer(hFile, DOSHeader->e_lfanew, NULL, FILE_BEGIN);

				// allocate a new buffer to hold the original PEHeader data
				ReadBuffer2 = VirtualAlloc(NULL, PEHeaderSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

				if(ReadBuffer2)
				{
					// read just the PEHeader data from the original file
					if(ReadFile(hFile, ReadBuffer2, PEHeaderSize, &BytesRead, NULL))
					{
						// change the page permissions to the memory where the original
						// PEHeader will be written
						if(VirtualProtectEx(hProc, (LPVOID)ImageBase, PEHeaderSize, PAGE_READWRITE, &OldProtect))
						{
							// write the original PEHeader data into the target process' PEHeader
							if(WriteProcessMemory(hProc, (LPVOID)((ULONG_PTR)ImageBase + DOSHeader->e_lfanew), ReadBuffer2, PEHeaderSize, &(SIZE_T)BytesWritten))
							{
								// restore old permissions
								VirtualProtectEx(hProc, (LPVOID)ImageBase, PEHeaderSize, OldProtect, &OldProtect);

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

int DumpMemoryRegion(void* addr, ULONGLONG size, int DumpType, BOOL PasteHeaderFromDisk, BOOL bFixHeader, HWND hwndOwner)
{
	HANDLE hProc, hFile;
	SIZE_T BytesRead;
	DWORD BytesWritten;
	LPVOID BaseAddress;
	OPENFILENAME ofn;
	char szFile[MAX_PATH], szProcName[MAX_PATH];

	BaseAddress = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if(BaseAddress)
	{
		hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, iGlobalPid);
		if(hProc != NULL)
		{
			if(ReadProcessMemory(hProc, (LPVOID)addr, BaseAddress, size, &(SIZE_T)BytesRead))
			{
				memset(&ofn, 0, sizeof(ofn));

				ofn.lStructSize = sizeof(OPENFILENAME);
				ofn.hwndOwner = hwndOwner;

				if(DumpType == DUMPREGION || DumpType == DUMPPARTIAL)
				{
					ofn.lpstrFilter = TEXT("Dump File *.DMP");
					ofn.lpstrTitle = TEXT("Save memory dump ...");

					sprintf_s(szFile,  sizeof(szFile), "addr=%0llX-size=%0llX.dmp", (ULONGLONG)addr, (ULONGLONG)size);
					ofn.lpstrFile = szFile;
				}
				else
				{
					GetModuleFileNameEx(hProc, NULL, szProcName, sizeof(szProcName)/sizeof(char));

					ofn.lpstrFilter = TEXT("Executable File *.EXE");
					ofn.lpstrTitle = TEXT("Save full dump ...");

					sprintf_s(szFile, sizeof(szFile), "dump-%s", PathFindFileName(szProcName));
					ofn.lpstrFile = szFile;
				}

				ofn.nMaxFile = sizeof(szFile)/sizeof(*szFile);
				ofn.lpstrFileTitle = NULL;
				ofn.lpstrInitialDir = (LPSTR)NULL;
				ofn.Flags = OFN_SHOWHELP | OFN_OVERWRITEPROMPT;
				
				GetModuleFileNameEx(hProc, NULL, szProcName, sizeof(szProcName)/sizeof(char));
				
				if(GetSaveFileName(&ofn))
				{
					hFile = CreateFile(ofn.lpstrFile, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
					if(hFile != NULL)
					{
						if(PasteHeaderFromDisk)
							PastePEHeader(hProc, (ULONGLONG)BaseAddress, szProcName);

						if(bFixHeader)
							FixHeader(hProc, (ULONGLONG)BaseAddress, szProcName);

						// When calling WriteFile() from a 64bit process with a BytesWritten variable == NULL
						// your app will crash, so, we MUST use a LPDWORD instead.
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
				//GetLastError();
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
	char szAddr[17], szSize[17];

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
				else
				{
					if(iSubItem == ITYPE_COLUMN)
					{
						if((ITypeSortOrder == NO_SORT) || (ITypeSortOrder == ITYPE_SORT_DESCENDING))
						{
							ListView_SortItems(MyhList, ListViewProcessesCompareProc, ITYPE_SORT_ASCENDING);
							UpdatelParam(MyhList);
							ITypeSortOrder = ITYPE_SORT_ASCENDING;
						}
						else
						{
							ListView_SortItems(MyhList, ListViewProcessesCompareProc, ITYPE_SORT_DESCENDING);
							UpdatelParam(MyhList);
							ITypeSortOrder = ITYPE_SORT_DESCENDING;
						}
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
								if(lParamSort == IZ_SORT_DESCENDING)
								{
									ListView_GetItemText(hList, lParam1, IZ_COLUMN, szText, sizeof(szText));
									ListView_GetItemText(hList, lParam2, IZ_COLUMN, szText2, sizeof(szText2));

									long num1 = strtol(szText, NULL, 16);
									long num2 = strtol(szText2, NULL, 16);

									retval = num2 - num1;
								}
								else
								{
									if(lParamSort == ITYPE_SORT_ASCENDING)
									{
										ListView_GetItemText(hList, lParam1, ITYPE_COLUMN, szText, sizeof(szText));
										ListView_GetItemText(hList, lParam2, ITYPE_COLUMN, szText2, sizeof(szText2));

										retval = lstrcmpi(szText, szText2);
									}
									else
									{
										ListView_GetItemText(hList, lParam1, ITYPE_COLUMN, szText, sizeof(szText));
										ListView_GetItemText(hList, lParam2, ITYPE_COLUMN, szText2, sizeof(szText2));

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
	LPVOID Address;

	hGlobal = GlobalAlloc(GHND, size);
	Address = GlobalLock(hGlobal);

	memcpy_s(Address, size, pMem, size);

	if(OpenClipboard(NULL))
	{
		EmptyClipboard();
		SetClipboardData(CF_TEXT, Address);
		CloseClipboard();
	}

	GlobalUnlock(hGlobal);
	GlobalFree(hGlobal);
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
	MessageBox(hDlg, TEXT("Virtual Section Dumper v1.0\n\nCoded by:\n\t +NCR/CRC! [ReVeRsEr]\n\ncrackinglandia(at)gmail(dot)com\n@crackinglandia\n\nGeneral Pico, La Pampa\nArgentina"), 
		TEXT("Virtual Section Dumper v1.0"),
		MB_ICONINFORMATION);
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
		
		lvCol.cx = lvCol.cxIdeal = 120;

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
	MEMORY_BASIC_INFORMATION64 mbi;
	SIZE_T numBytes;
	ULONGLONG MyAddress = 0, newAddress;
	LVITEM lvItem;
	int index = 0;
	char szText[17];

	hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, iGlobalPid);
	if(hProc != NULL)
	{
		// We load the VirtualQueryEx() function dinamycally to use the MEMORY_BASIC_INFORMATION64 structure
		// instead of MEMORY_BASIC_INFORMATION. You know another way to do it? write me an email ;P
		myVirtualQueryEx = (MYVIRTUALQUERYEX)GetProcAddress(GetModuleHandle(TEXT("kernel32")),"VirtualQueryEx");
		if(myVirtualQueryEx != NULL)
		{
			do
			{
				numBytes = myVirtualQueryEx(hProc, (LPCVOID)MyAddress, &mbi, sizeof(mbi));

				memset(&lvItem, 0, sizeof(lvItem));

				lvItem.mask = LVIF_TEXT | LVIF_PARAM;
				lvItem.cchTextMax = MAX_PATH;
				lvItem.iItem = lvItem.lParam = index;
				lvItem.iSubItem = 0;

				if(ListView_InsertItem(MyhList, &lvItem) != -1)
				{
					sprintf_s(szText, sizeof(szText), "%0llX", mbi.BaseAddress);
					ListView_SetItemText(MyhList, index, 0, szText);

					sprintf_s(szText, sizeof(szText), "%0llX", mbi.RegionSize);
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

				/* 
				This is to avoid an infinite loop produced by the erroneous data
				returned in the MEMORY_BASIC_INFORMATION structure when querying a 64bit
				process from a 64bit process.

				http://src.chromium.org/svn/trunk/src/base/process_util_win.cc
				*/

				//MyAddress += mbi.RegionSize;

				newAddress = (ULONGLONG)mbi.BaseAddress + mbi.RegionSize;
				if(newAddress <= MyAddress)
					numBytes = 0;
				else
					MyAddress = newAddress;

				index++;
			}
			while(numBytes);
		}
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
	char szAddr[17], szSize[17];
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

										DialogBoxParam(hGlobalInstance, (LPCTSTR)SECTIONSDLG, hDlg, (DLGPROC)DumpRegionProc, 0);
									}
									else
									{
										CloseHandle(hProc);
										MessageBox(hDlg, TEXT("The selected item is not a 32 bits process"), TEXT("Ups!"), MB_ICONERROR);
									}
								}
								else
									MessageBox(hDlg, TEXT("Couldn't not receive process handle!"), TEXT("VSD v1.0"), MB_ICONERROR);
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
			hMenu = CreatePopupMenu();
			AppendMenu(hMenu, MF_STRING, IDM_SELECTALL, TEXT("Select All"));
			AppendMenu(hMenu, MF_STRING, IDM_COPY2CLIPBOARD, TEXT("Copy to Clipboard"));
			InsertMenu(hMenu, 2, MF_SEPARATOR, 0, "-");
			AppendMenu(hMenu, MF_STRING, IDM_DUMP_FULL, TEXT("Dump Full ..."));
			AppendMenu(hMenu, MF_STRING, IDM_DUMP_PARTIAL, TEXT("Dump Partial ..."));
			AppendMenu(hMenu, MF_STRING, IDM_DUMP_REGION, TEXT("Dump Regions ..."));
			InsertMenu(hMenu, 2, MF_SEPARATOR, 0, "-");
			AppendMenu(hMenu, MF_STRING, IDM_DELPROCESS, TEXT("Kill Process"));
			InsertMenu(hMenu, 2, MF_SEPARATOR, 0, "-");
			AppendMenu(hMenu, MF_STRING, IDM_REFRESH, TEXT("Refresh"));

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
			SelItem = TrackPopupMenuEx(hMenu, TPM_RETURNCMD, pt.x, pt.y, hDlg, NULL);

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
									// close the handle of the process
									CloseHandle(hProc);
									// update the processes listview
									Sleep(500);
									ListView_DeleteAllItems(hList);
									ListProcesses(hDlg, hList);
								}
								else
								{
									CloseHandle(hProc);
									MessageBox(hDlg, TEXT("The selected item is not a 32 bits process"), TEXT("Ups!"), MB_ICONERROR);
								}
							}
							else
								MessageBox(hDlg, TEXT("Couldn't terminate process!"), TEXT("Terminate Process"), MB_ICONERROR);
						}
					}
					break;

				case IDM_REFRESH:
					ListView_DeleteAllItems(hList);
					ListProcesses(hDlg, hList);
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
								CloseHandle(hProc);

								iGlobalPid = iPid;

								DialogBoxParam(hGlobalInstance, (LPCTSTR)PARTIALDUMP, hDlg, (DLGPROC)PartialDumpProc, 0);
							}
							else
							{
								CloseHandle(hProc);
								MessageBox(hDlg, TEXT("The selected item is not a 32 bits process"), TEXT("Ups!"), MB_ICONERROR);
							}
						}
						else
						{
							MessageBox(hDlg, TEXT("Couldn't receive process handle!"), TEXT("VSD v1.0"), MB_ICONERROR);
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
								CloseHandle(hProc);

								iGlobalPid = iPid;
								
								ListView_GetItemText(hList, item, IB_COLUMN, szAddr, sizeof(szAddr));
								ListView_GetItemText(hList, item, IZ_COLUMN, szSize, sizeof(szSize));

								BOOL bPasteHeader = IsDlgButtonChecked(hDlg, PASTEPEHEADER);
								BOOL bFixHeader = IsDlgButtonChecked(hDlg, FIXPEHEADER);

								retval = DumpMemoryRegion((void*)_strtoi64(szAddr, NULL, 16), _strtoi64(szSize, NULL, 16), DUMPFULL, bPasteHeader, bFixHeader,  hDlg);

								ValidateResult(retval);
							}
							else
							{
								CloseHandle(hProc);
								MessageBox(hDlg, TEXT("The selected item is not a 32 bits process"), TEXT("Ups!"), MB_ICONERROR);
							}
						}
						else
							MessageBox(hDlg, TEXT("Couldn't receive process handle!"), TEXT("VSD v1.0"), MB_ICONERROR);
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

								// close the handle of the process
								CloseHandle(hProc);

								// create the Dialog to show the virtual sections of the corresponding process
								DialogBoxParam(hGlobalInstance, (LPCTSTR)SECTIONSDLG, hDlg, (DLGPROC)DumpRegionProc, 0);
							}
							else
							{
								CloseHandle(hProc);
								MessageBox(hDlg, TEXT("The selected item is not a 32 bits process"), TEXT("Ups!"), MB_ICONERROR);
							}
						}
						else
							MessageBox(hDlg, TEXT("Couldn't receive process handle!"), TEXT("VSD v1.0"), MB_ICONERROR);
					}
					break;

				case IDM_COPY2CLIPBOARD:
					CopyDataToClipBoard(hList, MAX_COLS);
					break;

				case IDM_SELECTALL:
					SelectAllItems(hList);
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

				case EXCLUDE_X64_PROCS:
					RefreshLV(hDlg, hList);
					break;

				case BT_REFRESH:
					RefreshLV(hDlg, hList);
					break;

				case BT_ABOUT:
					ShowAboutInfo(hDlg);
					break;

				case IDCANCEL:
					if(MessageBox(hDlg, TEXT("Are you sure you want to quit?"), TEXT("Exit VSD?"), MB_YESNO) == IDYES)
					{
						DestroyMenu(hMenu);
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

BOOL CALLBACK DumpRegionProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	DWORD SetItem;
	int iPos, retval, iPerPage, CurPos, iTop, lastItem;
	HWND hAddrEdit, hSizeEdit;
	char Address[17], Size[17];

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

			// get handles for editboxes controls
			hAddrEdit = GetDlgItem(hDlg, ADDRESS_EDIT);
			hSizeEdit = GetDlgItem(hDlg, SIZE_EDIT);

			Edit_LimitText(hAddrEdit, 16);
			Edit_LimitText(hSizeEdit, 16);

			hCopy2Clip = CreatePopupMenu();
			AppendMenu(hCopy2Clip, MF_STRING, IDM_SELECTALL, TEXT("Select All"));
			AppendMenu(hCopy2Clip, MF_STRING, IDM_COPY2CLIPBOARD, TEXT("Copy to Clipboard"));

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
					if(GetDlgItemText(hDlg, ADDRESS_EDIT,  Address, 17))
					{
						if(IsValidHexString(Address))
						{
							if(GetDlgItemText(hDlg, SIZE_EDIT, Size, 17))
							{
								if(IsValidHexString(Size))
								{
									retval = DumpMemoryRegion((void*)_strtoi64(Address, NULL, 16), _strtoi64(Size, NULL, 16), DUMPREGION, FALSE, FALSE, hDlg);
									ValidateResult(retval);
								}
								else
								{
									MessageBox(hDlg, TEXT("The value entered as Size is not a valid hex number"), "Ups!", MB_ICONERROR);
								}
							}
							else
							{
								MessageBox(hDlg, TEXT("You didn't enter the Size"), "Are you kidding?", MB_ICONERROR);
							}
						}
						else
						{
							MessageBox(hDlg, TEXT("The value entered as Address is not a valid hex number"), "Ups!", MB_ICONERROR);
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
	char* lvColTitles[] = {"Path", "PID", "ImageBase", "ImageSize", "ImageType"};
	char szFmtText[MAX_PATH];

	for(index = 0; index < MAX_COLS; index++)
	{
		lvCol.mask = LVCF_TEXT | LVCF_SUBITEM | LVCF_WIDTH | LVCF_IDEALWIDTH;
		lvCol.pszText = lvColTitles[index];
		lvCol.cx = lvCol.cxIdeal = 120;

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

							EnumProcessModulesEx(hProc, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL);
							if(GetModuleInformation(hProc, hMods[0], &modInfo, sizeof(modInfo)))
							{
								// to print a 64bit number we should use "ll" (long long)
								sprintf_s(szText, sizeof(szText), "%0llX", modInfo.lpBaseOfDll);
								ListView_SetItemText(MyhList, iCount, 2, szText);

								sprintf_s(szText, sizeof(szText), "%0llX", modInfo.SizeOfImage);
								ListView_SetItemText(MyhList, iCount, 3, szText);
							}
							else
							{
								ListView_SetItemText(MyhList, iCount, 0, "System Idle Process");
								ListView_SetItemText(MyhList, iCount, 2, "0");
								ListView_SetItemText(MyhList, iCount, 3, "0");
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

						ListView_SetItemText(MyhList, iCount, 2, "0");
						ListView_SetItemText(MyhList, iCount, 3, "0");
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

						EnumProcessModulesEx(hProc, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL);
						if(GetModuleInformation(hProc, hMods[0], &modInfo, sizeof(modInfo)))
						{
							// to print a 64bit number we should use "ll" (long long)
							sprintf_s(szText, sizeof(szText), "%0llX", modInfo.lpBaseOfDll);
							ListView_SetItemText(MyhList, proc_count, 2, szText);

							sprintf_s(szText, sizeof(szText), "%0llX", modInfo.SizeOfImage);
							ListView_SetItemText(MyhList, proc_count, 3, szText);

							if(IsWow64(hProc))
							{
								ListView_SetItemText(MyhList, proc_count, 4, TEXT("32-bit"));
							}
							else
							{
								ListView_SetItemText(MyhList, proc_count, 4, TEXT("64-bit"));
							}
						}
						else
						{
							ListView_SetItemText(MyhList, proc_count, 0, "System Idle Process");
							ListView_SetItemText(MyhList, proc_count, 2, "0");
							ListView_SetItemText(MyhList, proc_count, 3, "0");
							ListView_SetItemText(MyhList, proc_count, 4, TEXT("n/a"));
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

						ListView_SetItemText(MyhList, proc_count, 2, "0");
						ListView_SetItemText(MyhList, proc_count, 3, "0");
						ListView_SetItemText(MyhList, proc_count, 4, "n/a");
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
