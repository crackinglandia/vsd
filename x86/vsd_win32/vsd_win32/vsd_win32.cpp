/* 
$Id: vsd_win32.cpp 18 2012-04-01 19:27:27Z crackinglandia $

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

#include "vsd.h"

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	hGlobalInstance = hInstance;

	InitCommonControls();
	DialogBoxParam(hInstance, (LPCTSTR)VSDDLG, 0, AppDlgProc, 0);

	return 0;
}