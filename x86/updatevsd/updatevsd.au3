#cs
	$Id: updatevsd.au3 54 2012-06-03 02:31:05Z crackinglandia $

	UpdateVSD v0.1
	
	Copyright (C) 2012 UlisesSoft http://web.ulisessoft.info
	
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
#ce


#region ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_Version=beta
#AutoIt3Wrapper_icon=icono.ico
#AutoIt3Wrapper_outfile=updatevsd.exe
#AutoIt3Wrapper_Compression=4
#AutoIt3Wrapper_Res_Comment=UpdateVSD
#AutoIt3Wrapper_Res_Description=UpdateVSD
#AutoIt3Wrapper_Res_Fileversion=0.1.0.0
#AutoIt3Wrapper_Res_LegalCopyright=UlisesSoft
#AutoIt3Wrapper_Res_requestedExecutionLevel=requireAdministrator
#AutoIt3Wrapper_Run_Tidy=y
#endregion ;**** Directives created by AutoIt3Wrapper_GUI ****

#include <GUIConstantsEx.au3>
#include <WindowsConstants.au3>
#include <ProgressConstants.au3>
#include <EditConstants.au3>
#include <SendMessage.au3>
#include <INet.au3>
#include <Array.au3>
#include<WinAPI.au3>

Opt("TrayMenuMode", 1)
TraySetState()

Global $Param[4], $ArrayOnline[100][3], $ArrayLocal[100][3], $ArrayQuestion[100][3], $temp[100], $ArrayDIR[100]
Global $MODE_MANUAL, $MODE_START, $MODE_AUTO, $QUESTION, $PROXY, $LAST_UPDATE, $AMOUNT_UPDATE, $COUNT_UPDATE

Global $tname = "UpdateVSD"
Global $version = "0.1"
Global $startON = 0
Global $font = "Tahoma"

Global $Gui_start

FileInstall("logovsd.jpg", @TempDir & "\logovsd.jpg")
Global $logo = @TempDir & "\logovsd.jpg"
Global $DirLocal = @ScriptDir

$date = @MDAY & "/" & @MON & "/" & @YEAR
$time = @HOUR & ":" & @MIN
$txtlog = $date & " - " & $time

;Versión para compilar
$system = "x86" ; compilar 32bits
;$system = "x64" ; compilar 64bits

$list = ProcessList(@ScriptName)
$cont = $list[0][0]
If $cont > 1 Then
	Exit
EndIf

Sleep(500)

If True Then
	;Actualización de si mismo
	$filenameori = "updatevsd.exe"
	$filenameupd = "updatevsdnew.exe"
	$filename = @ScriptName

	If $filename = "updatevsd.exe" Or $filename = "updatevsdnew.exe" Then
		If $filename <> $filenameori Then
			If $filename <> $filenameupd Then
				FileCopy($filename, $filenameori, 1)
				Sleep(500)
				Run($filenameori & " /kill " & $filename)
				Exit
			Else
				Sleep(500)
				FileCopy($filename, $filenameori, 1)
				Sleep(500)
				Run($filenameori)
				Exit
			EndIf
		Else
			If FileExists($filenameupd) Then
				$crc32upd = _CRC32($filenameupd)
				$crc32file = _CRC32($filename)
				If $crc32upd = $crc32file Then
					FileDelete($filenameupd)
				Else
					Run($filenameupd)
					Exit
				EndIf
			EndIf
		EndIf
	Else
		FileCopy($filename, $filenameori, 1)
		Sleep(500)
		Run($filenameori & " /kill " & $filename)
		Exit
	EndIf
EndIf

;Parametros
For $x = 1 To $CMDLINE[0]
	$T_VAR = StringLower($CMDLINE[$x])
	Select
		Case $T_VAR = "/kill"
			$Param[0] = 1
			If StringRight($CMDLINE[2], 4) = ".exe" Then
				$filekill = $CMDLINE[2]
			Else
				$filekill = $CMDLINE[2] & " " & $CMDLINE[3]
			EndIf
			;_ArrayDisplay($CMDLINE)
		Case $T_VAR = "/settings"
			$Param[1] = 1
		Case $T_VAR = "/help" Or $T_VAR = "/h" Or $T_VAR = "-help" Or $T_VAR = "--help" Or $T_VAR = "-h" Or $T_VAR = "/?"
			$Param[2] = 1
		Case $T_VAR = "/history"
			$Param[3] = 1
	EndSelect
Next

Select
	Case $Param[0] = 1
		$kill1 = _CRC32(@ScriptName)
		$kill2 = _CRC32($filekill)
		;compara si el crc32 es el mismo
		If $kill1 = $kill2 Then FileDelete($filekill)
	Case $Param[1] = 1
		Settings()
		Exit
	Case $Param[2] = 1
		_help()
		Exit
	Case $Param[3] = 1
		_history()
		Exit
EndSelect

;$UPDATE_DATE = "" ; <--- revisar pendiente
$LAST_UPDATE = ""
$AMOUNT_UPDATE = 0
$COUNT_UPDATE = 3

If FileExists("updatevsd.ini") Then
	$LAST_UPDATE = IniRead("updatevsd.ini", "UPDATE", "LAST_UPDATE", "")
	$AMOUNT_UPDATE = IniRead("updatevsd.ini", "UPDATE", "AMOUNT_UPDATE", 0)
	$COUNT_UPDATE = IniRead("updatevsd.ini", "UPDATE", "COUNT_UPDATE", 3)

	$MODE_MANUAL = IniRead("updatevsd.ini", "UPDATE", "MODE_MANUAL", 0)
	$MODE_START = IniRead("updatevsd.ini", "UPDATE", "MODE_START", 0)
	$MODE_AUTO = IniRead("updatevsd.ini", "UPDATE", "MODE_AUTO", 0)
	$QUESTION = IniRead("updatevsd.ini", "UPDATE", "QUESTION", 0)
	$PROXY = IniRead("updatevsd.in", "PROXY", "P_AUTO", 0)
EndIf

;17/05/2012 - 15:27
If ($MODE_START = 1) Or ($MODE_AUTO = 1) Then
	If StringLeft($LAST_UPDATE, 10) = $date Then
		If $AMOUNT_UPDATE > ($COUNT_UPDATE - 1) Then
			Exit
		EndIf
	Else
		IniWrite("updatevsd.ini", "UPDATE", "AMOUNT_UPDATE", 0)
		$AMOUNT_UPDATE = 0
	EndIf
	Start()
Else
	_proxy()
	_carpetas()
	_online()
	_local()
	_compare()
EndIf



Func Start()

	Global $msg, $logo, $progress, $about, $title, $msn, $Gui_start, $update

	$Gui_start = GUICreate($tname, 317, 115, -1, -1, $WS_POPUPWINDOW, $WS_EX_TOPMOST + $WS_EX_TOOLWINDOW)
	$logo = GUICtrlCreatePic($logo, 0, 0, 317, 44)
	$progress = GUICtrlCreateProgress(0, 44, 317, 10, $PBS_MARQUEE)
	GUICtrlSetColor(-1, 0x008000)
	GUISetFont(8, 400, 1, $font)
	$title = GUICtrlCreateLabel("Update VSD", 5, 60, 250)
	GUISetFont(8, 400, 1, $font)
	$msn = GUICtrlCreateLabel("Starting update...", 5, 75, 300)
	GUISetFont(7, 400, 1, $font)
	$update = GUICtrlCreateLabel("Last updated " & $LAST_UPDATE, 5, 100, 180, 20)

	GUISetFont(7, 400, 1, $font)
	$about = GUICtrlCreateLabel("UpdateVSD " & $version, 248, 100, 70, 20)
	GUICtrlSetState($about, $GUI_DISABLE)

	_SendMessage(GUICtrlGetHandle($progress), $PBM_SETMARQUEE, True, 20)
	GUISetState(@SW_SHOW)

	$startON = 1
	_proxy()
	_carpetas()
	_online()
	_local()
	_compare()

	Exit
EndFunc   ;==>Start


Func _carpetas()

	Local $a = 1

	If $startON = 1 Then
		GUICtrlSetData($tname, "Reviewing files online...")
		GUICtrlSetData($msn, "Checking...")
	Else
		TrayTip($tname & " " & $version, "Reviewing files online... " & @CR & "Checking..." & @CR & @CR & "VSD Virtual Section Dumper", 5, 1)
	EndIf

	$linkGcodeLis = "http://code.google.com/p/virtualsectiondumper/source/browse/trunk/" & $system & "/stable/"

	$GcodeHtml = _INetGetSource($linkGcodeLis)

	If $GcodeHtml = "" Then
		If $startON = 1 Then
			GUICtrlSetData($title, "Cannot connect to server")
			GUICtrlSetData($msn, "Check you internet connection or your proxy configuration")
		Else
			TrayTip($tname & " " & $version, "Cannot connect to server" & @CR & "Check you internet connection or your proxy configuration" & @CR & @CR & "VSD Virtual Section Dumper", 1, 3)
		EndIf
		Sleep(4000)
		Exit
	EndIf
	$ArrayHtml = StringSplit($GcodeHtml, "<")

	For $i = 0 To $ArrayHtml[0]
		$ex1 = StringLeft($ArrayHtml[$i], 1)
		$ex2 = StringInStr($ArrayHtml[$i], '"return false"')
		$ex3 = StringInStr($ArrayHtml[$i], "href")

		If $ex1 = "a" And $ex2 > 0 And $ex3 > 0 Then
			$tstring = StringLen($ArrayHtml[$i])
			$posA = $ex3 + 6
			$posB = ($tstring - $posA) + 1
			$carpl = StringMid($ArrayHtml[$i], $posA, $posB)

			$ex1 = StringInStr($carpl, '"')
			$tstring = StringLen($carpl)
			$posA = $ex1 + 2
			$posB = ($tstring - $posA) + 1
			$carp = StringMid($carpl, $posA, $posB)
			If $ex1 > 2 Then
				$ArrayDIR[0] = $a
				$ArrayDIR[$a] = $system & "/" & $carp
				$a = $a + 1
			EndIf
		EndIf
	Next
EndFunc   ;==>_carpetas



Func _online()

	Local $arr = 0
	$linkGcodeLis = "http://code.google.com/p/virtualsectiondumper/source/browse/trunk/" & $system & "/stable/"

	$GcodeHtml = _INetGetSource($linkGcodeLis)

	If $GcodeHtml = "" Then
		If $startON = 1 Then
			GUICtrlSetData($title, "Cannot connect to server")
			GUICtrlSetData($msn, "Check you internet connection or your proxy configuration")
		Else
			TrayTip($tname & " " & $version, "Cannot connect to server" & @CR & "Check you internet connection or your proxy configuration" & @CR & @CR & "VSD Virtual Section Dumper", 1, 3)
		EndIf
		Sleep(4000)
		Exit
	EndIf

	$ArrayHtml = StringSplit($GcodeHtml, "{")
	For $i = 0 To $ArrayHtml[0]

		$txt = ':['
		$cont = StringLen($txt)
		$posA = StringInStr($ArrayHtml[$i], $txt)

		If $posA > 1 Then

			$href = StringLeft($ArrayHtml[$i], 1)

			If $href = '"' Then

				$clean = StringRegExpReplace($ArrayHtml[$i], "[,:]", "")
				$ArraySVN = StringSplit($clean, '"')
				For $a = 1 To $ArraySVN[0]

					$ext = StringRight($ArraySVN[$a], 4)
					$ext = StringLeft($ext, 1)
					If ($ext = ".") Or ($ArraySVN[$a] = "LICENSE") Then

						$dir = @TempDir & "\update\"
						$exis = FileExists($dir)
						If $exis = 0 Then
							DirCreate($dir)
						EndIf
						$size = InetGetSize("http://virtualsectiondumper.googlecode.com/svn/trunk/" & $system & "/stable/" & $ArraySVN[$a])
						If $size > 0 Then
							$Link = "http://virtualsectiondumper.googlecode.com/svn/trunk/" & $system & "/stable/" & $ArraySVN[$a]

							If $startON = 1 Then
								GUICtrlSetData($title, "Reviewing files online... ")
								GUICtrlSetData($msn, $ArraySVN[$a])
							Else
								TrayTip($tname & " " & $version, "Reviewing files online... " & @CR & $ArraySVN[$a] & @CR & @CR & "VSD Virtual Section Dumper", 5, 1)
							EndIf
							InetGet($Link, $dir & "\" & $ArraySVN[$a], 1)

							$crc32online = _CRC32($dir & "\" & $ArraySVN[$a])

							$ArrayOnline[$arr][0] = $ArraySVN[$a]
							$ArrayOnline[$arr][1] = $dir & "\" & $ArraySVN[$a]
							$ArrayOnline[$arr][2] = $crc32online
							$arr = $arr + 1
						EndIf
					EndIf
				Next
			EndIf
		EndIf
	Next
EndFunc   ;==>_online


Func _local()

	$temp = _FileListToArray_Recursive($DirLocal & "\", "*.*", 1, 0, 0)
	$ar = 0

	For $x = 1 To $temp[0]
		$ArrayLocal[$ar][0] = $temp[$x]
		$ar = $ar + 1
		If $x = 99 Then ExitLoop
	Next

	$ar = 0
	$temp = _FileListToArray_Recursive($DirLocal & "\", "*.*", 1, 2, 0)

	For $x = 1 To $temp[0]
		$ArrayLocal[$ar][1] = $temp[$x]
		$ar = $ar + 1
		If $x = 99 Then ExitLoop
	Next


	$ar = 0
	For $x = 1 To 99
		$filelocal = $ArrayLocal[$ar][1]

		If $filelocal = "" Then ExitLoop

		$crc32local = _CRC32($filelocal)
		$ArrayLocal[$ar][2] = $crc32local
		$ar = $ar + 1
	Next

EndFunc   ;==>_local

Func _compare()

	Local $ListUpdate = ""
	Local $run = 0
	Local $upd = 0
	Local $new = 0
	Local $z = 0
	FileWriteLine("updatevsd.log", @CRLF)
	FileWriteLine("updatevsd.log", "-- Starting Update -- " & $txtlog)

	For $x = 0 To 99

		$ncarpf = $DirLocal & "\"

		$name = $ArrayOnline[$x][0]

		If $name = "" Then ExitLoop

		$carp = $ArrayOnline[$x][1]

		$pos1 = StringInStr($carp, "\update\")
		$final = StringInStr($carp, $name)
		$pos2 = $final - $pos1
		$uvi = StringMid($carp, $pos1 + 8, $pos2 - 8)

		StringReplace($carp, "\", "-")
		$num = @extended

		$nom = StringInStr($carp, "\", 0, $num - 1)
		$ncarp = StringMid($carp, $nom + 1, 3)


		$p = _ArraySearch($ArrayLocal, $name, 0, 0, 0, 0, 1, 0)
		If @error Then

			$new = $new + 1
			$z = $z + 1

			If $name = "UpdateVSD.exe" Then

				$ArrayQuestion[$z][0] = $ArrayOnline[$x][1]
				$ArrayQuestion[$z][1] = $ncarpf & "UpdateVSDNew.exe"
				$ArrayQuestion[$z][2] = "New file: " & $name
				;
			Else
				$ArrayQuestion[$z][0] = $ArrayOnline[$x][1]
				$ArrayQuestion[$z][1] = $ncarpf & $ArrayOnline[$x][0]
				$ArrayQuestion[$z][2] = "New file: " & $name

			EndIf
			$ListUpdate = $ListUpdate & $name & @CR

		Else

			If $ArrayOnline[$x][2] <> $ArrayLocal[$p][2] Then

				$upd = $upd + 1
				$z = $z + 1

				If $name = "vsd_win32.exe" Then
					If ProcessExists("vsd_win32.exe") Then
						$run = 1
						ProcessClose("vsd_win32.exe")
					EndIf
				EndIf

				If $name = "Updatevsd.exe" Then
					$ArrayQuestion[$z][0] = $ArrayOnline[$x][1]
					$ArrayQuestion[$z][1] = $ncarpf & "Updatevsdnew.exe"
					$ArrayQuestion[$z][2] = "Update file: " & $name

				Else
					$ArrayQuestion[$z][0] = $ArrayOnline[$x][1]
					$ArrayQuestion[$z][1] = $ncarpf & $ArrayOnline[$x][0]
					$ArrayQuestion[$z][2] = "Update file: " & $name

				EndIf
				$ListUpdate = $ListUpdate & $name & @CR
			EndIf
		EndIf

	Next

	If $new = 0 And $upd = 0 Then
		FileWriteLine("updatevsd.log", "- No files to update")
		If $startON = 1 Then
			GUICtrlSetData($title, "VSD is already updated")
			GUICtrlSetData($msn, "No files to update")
		Else
			TrayTip($tname & " " & $version, "VSD is already updated" & @CR & "no files to update" & @CR & @CR & "VSD Virtual Section Dumper", 5, 1)
		EndIf

	Else

		$x = $new + $upd

		If $QUESTION = 0 And $MODE_AUTO = 0 Then
			TrayTip("clears", "", 0)
			GUISetState(@SW_HIDE, $Gui_start)
			$option = MsgBox(32 + 4, $tname, $x & " new files were found" & @CR & @CR & $ListUpdate & @CR & "¿Do you want to update the files?")
			GUISetState(@SW_SHOW, $Gui_start)
		Else
			$option = 6
		EndIf

		If $option = 6 Then

			For $a = 1 To $x

				If $startON = 1 Then
					GUICtrlSetData($title, "Updating...")
					GUICtrlSetData($msn, $ArrayQuestion[$a][2])
				Else
					TrayTip($tname & " " & $version, "Updating..." & @CR & $ArrayQuestion[$a][2] & @CR & @CR & "VSD Virtual Section Dumper", 5, 1)
				EndIf
				Sleep(2000)
				FileCopy($ArrayQuestion[$a][0], $ArrayQuestion[$a][1], 9)
				FileWriteLine("updatevsd.log", "- " & $ArrayQuestion[$a][2])
			Next

			If $startON = 1 Then
				GUICtrlSetData($title, "New files : [" & $new & "]")
				GUICtrlSetData($msn, "Updated files : [" & $upd & "]")
			Else
				TrayTip($tname & " " & $version, "New files  : [" & $new & "]" & @CR & "Updated files : [" & $upd & "]" & @CR & @CR & "VSD Virtual Section Dumper", 5, 1)
			EndIf

			If $run = 1 Then ShellExecute(@ScriptDir & "\vsd_win32.exe")
		Else
			If $option = 7 Then

				If $startON = 1 Then
					GUICtrlSetData($title, "Updated canceled")
					GUICtrlSetData($msn, "")
				Else
					TrayTip($tname & " " & $version, "Updated canceled" & @CR & @CR & "VSD Virtual Section Dumper", 5, 1)
				EndIf
			Else
				If $startON = 1 Then
					GUICtrlSetData($title, "Update canceled")
					GUICtrlSetData($msn, "")
				Else
					TrayTip($tname & " " & $version, "Updated canceled" & @CR & @CR & "VSD Virtual Section Dumper", 5, 1)
				EndIf
			EndIf
		EndIf
	EndIf

	FileWriteLine("updatevsd.log", "-- Ending update --")
	IniWrite("updatevsd.ini", "UPDATE", "LAST_UPDATE", $txtlog)
	IniWrite("updatevsd.ini", "UPDATE", "AMOUNT_UPDATE", $AMOUNT_UPDATE + 1)
	Sleep(4000)
EndFunc   ;==>_compare


Func Settings()

	Local $config, $url, $prt, $puser, $ppass, $botonGuardar, $botonSalir, $sIni, $sData, $urltxt, $prttxt, $pusertxt, $ppasstxt, $lastupdate, $amoutupdate, $countupdate

	$urltxt = IniRead("updatevsd.ini", "PROXY", "P_URL", "")
	$prttxt = IniRead("updatevsd.ini", "PROXY", "P_PRT", "")
	$pusertxt = IniRead("updatevsd.ini", "PROXY", "P_USER", "")
	$ppasstxt = IniRead("updatevsd.ini", "PROXY", "P_PASS", "")
	$pautotxt = IniRead("updatevsd.ini", "PROXY", "P_AUTO", "")

	$modo1 = IniRead("updatevsd.ini", "UPDATE", "MODE_MANUAL", "")
	$modo2 = IniRead("updatevsd.ini", "UPDATE", "MODE_START", "")
	$modo3 = IniRead("updatevsd.ini", "UPDATE", "MODE_AUTO", "")
	$check = IniRead("updatevsd.ini", "UPDATE", "QUESTION", "")

	$lastupdate = IniRead("updatevsd.ini", "UPDATE", "LAST_UPDATE", "")
	$amoutupdate = IniRead("updatevsd.ini", "UPDATE", "AMOUNT_UPDATE", 0)
	$countupdate = IniRead("updatevsd.ini", "UPDATE", "COUNT_UPDATE", 3)

	$config = GUICreate("Settings", 255, 280, -1, -1, $WS_BORDER)

	GUICtrlCreateTab(10, 5, 230, 220)
	GUICtrlCreateTabItem("Update")

	GUICtrlCreateGroup("Update Settings", 20, 35, 210, 175)

	$radio1 = GUICtrlCreateRadio("Update manually", 30, 55, 120, 20)
	$check1 = GUICtrlCreateCheckbox("Do not prompt before updating", 50, 75, 175, 20)
	$radio2 = GUICtrlCreateRadio("Update when starting the program", 30, 105, 180, 20)
	$check2 = GUICtrlCreateCheckbox("Do not prompt before updating", 50, 125, 175, 20)
	$radio3 = GUICtrlCreateRadio("Automatic update mode", 30, 155, 175, 20)
	$day = GUICtrlCreateLabel("Updates by day :", 48, 188, 90, 20)
	$count = GUICtrlCreateInput($countupdate, 140, 184, 30, 20, $ES_CENTER)
	GUICtrlSetLimit($count, 1, 1)
	$Updown = GUICtrlCreateUpdown($count)
	GUICtrlSetLimit($Updown, 9, 1)
	GUICtrlSetState($count, $GUI_DISABLE)
	GUICtrlSetState($Updown, $GUI_DISABLE)
	GUICtrlSetState($day, $GUI_DISABLE)

	If $modo1 = 1 Then
		GUICtrlSetState($radio1, $GUI_CHECKED)
		If $check > 0 Then GUICtrlSetState($check1, $GUI_CHECKED)
		GUICtrlSetState($check2, $GUI_DISABLE)

		GUICtrlSetState($count, $GUI_DISABLE)
		GUICtrlSetState($Updown, $GUI_DISABLE)
		GUICtrlSetState($day, $GUI_DISABLE)
	Else
		If $modo2 = 1 Then
			GUICtrlSetState($radio2, $GUI_CHECKED)
			If $check > 0 Then GUICtrlSetState($check2, $GUI_CHECKED)
			GUICtrlSetState($check1, $GUI_DISABLE)

			GUICtrlSetState($count, $GUI_ENABLE)
			GUICtrlSetState($Updown, $GUI_ENABLE)
			GUICtrlSetState($day, $GUI_ENABLE)
		Else
			If $modo3 = 1 Then
				GUICtrlSetState($radio3, $GUI_CHECKED)
				GUICtrlSetState($check1, $GUI_DISABLE)
				GUICtrlSetState($check2, $GUI_DISABLE)

				GUICtrlSetState($count, $GUI_ENABLE)
				GUICtrlSetState($Updown, $GUI_ENABLE)
				GUICtrlSetState($day, $GUI_ENABLE)
			Else
				GUICtrlSetState($radio1, $GUI_CHECKED)
				GUICtrlSetState($check1, $GUI_ENABLE)
				GUICtrlSetState($check2, $GUI_DISABLE)
			EndIf
		EndIf
	EndIf


	GUICtrlCreateTabItem("Proxy")
	Local $d = 27
	Local $a = 55
	Local $d1 = 85

	GUICtrlCreateGroup("Proxy Settings", 20, 35, 210, 175)

	$autoproxy = GUICtrlCreateCheckbox("Use IE proxy settings", $d, $a, 150, 20)

	GUICtrlCreateLabel("IP or URL :", $d, $a + 35)
	$url = GUICtrlCreateInput($urltxt, $d1, $a + 30, 130, 20)

	GUICtrlCreateLabel("Port :", $d, $a + 65)
	$prt = GUICtrlCreateInput($prttxt, $d1, $a + 60, 40, 20)

	GUICtrlCreateLabel("User :", $d, $a + 95)
	$puser = GUICtrlCreateInput($pusertxt, $d1, $a + 90, 130, 20)

	GUICtrlCreateLabel("Password :", $d, $a + 125)
	$ppass = GUICtrlCreateInput($ppasstxt, $d1, $a + 120, 130, 20)

	If $pautotxt = 1 Then
		GUICtrlSetState($autoproxy, $GUI_CHECKED)
		GUICtrlSetState($url, $GUI_DISABLE)
		GUICtrlSetState($prt, $GUI_DISABLE)
		GUICtrlSetState($puser, $GUI_DISABLE)
		GUICtrlSetState($ppass, $GUI_DISABLE)
	EndIf

	GUICtrlCreateTabItem("") ; end tabitem definition

	$botonGuardar = GUICtrlCreateButton("Save", 40, 230, 80, 20)
	$botonSalir = GUICtrlCreateButton("Exit", 135, 230, 80, 20)

	GUISetState(@SW_SHOW)


	While 1

		Local $msgc = GUIGetMsg()
		Switch $msgc
			Case $GUI_EVENT_CLOSE
				Exit
			Case $radio1
				GUICtrlSetState($check2, $GUI_UNCHECKED)
				GUICtrlSetState($check2, $GUI_DISABLE)
				GUICtrlSetState($check1, $GUI_ENABLE)

				GUICtrlSetState($count, $GUI_DISABLE)
				GUICtrlSetState($Updown, $GUI_DISABLE)
				GUICtrlSetState($day, $GUI_DISABLE)
			Case $radio2
				GUICtrlSetState($check1, $GUI_UNCHECKED)
				GUICtrlSetState($check1, $GUI_DISABLE)
				GUICtrlSetState($check2, $GUI_ENABLE)

				GUICtrlSetState($count, $GUI_ENABLE)
				GUICtrlSetState($Updown, $GUI_ENABLE)
				GUICtrlSetState($day, $GUI_ENABLE)
				$amoutupdate = 0

			Case $radio3
				GUICtrlSetState($check1, $GUI_UNCHECKED)
				GUICtrlSetState($check2, $GUI_UNCHECKED)

				GUICtrlSetState($check1, $GUI_DISABLE)
				GUICtrlSetState($check2, $GUI_DISABLE)

				GUICtrlSetState($count, $GUI_ENABLE)
				GUICtrlSetState($Updown, $GUI_ENABLE)
				GUICtrlSetState($day, $GUI_ENABLE)
				$amoutupdate = 0
			Case $botonGuardar

				$sIni = @ScriptDir & "\updatevsd.ini"

				$sData = "MODE_MANUAL=" & BitAND(GUICtrlRead($radio1), $GUI_CHECKED) & @LF & "MODE_START=" & BitAND(GUICtrlRead($radio2), $GUI_CHECKED) & @LF & "MODE_AUTO=" & BitAND(GUICtrlRead($radio3), $GUI_CHECKED) & @LF & "QUESTION=" & BitAND(GUICtrlRead($check1), $GUI_CHECKED) + BitAND(GUICtrlRead($check2), $GUI_CHECKED) & @LF & "LAST_UPDATE=" & $lastupdate & @LF & "AMOUNT_UPDATE=" & $amoutupdate & @LF & "COUNT_UPDATE=" & GUICtrlRead($count)
				IniWriteSection($sIni, "UPDATE", $sData)
				$sData = "P_URL=" & GUICtrlRead($url) & @LF & "P_PRT=" & GUICtrlRead($prt) & @LF & "P_USER=" & GUICtrlRead($puser) & @LF & "P_PASS=" & GUICtrlRead($ppass) & @LF & "P_AUTO=" & BitAND(GUICtrlRead($autoproxy), $GUI_CHECKED)
				IniWriteSection($sIni, "PROXY", $sData)

				$modo1 = IniRead("updatevsd.ini", "UPDATE", "MODE_MANUAL", "")
				$modo2 = IniRead("updatevsd.ini", "UPDATE", "MODE_START", "")
				$modo3 = IniRead("updatevsd.ini", "UPDATE", "MODE_AUTO", "")
				$check = IniRead("updatevsd.ini", "UPDATE", "QUESTION", "")

				ExitLoop
			Case $autoproxy
				;MsgBox
				If BitAND(GUICtrlRead($autoproxy), $GUI_CHECKED) = 1 Then
					GUICtrlSetState($url, $GUI_DISABLE)
					GUICtrlSetState($prt, $GUI_DISABLE)
					GUICtrlSetState($puser, $GUI_DISABLE)
					GUICtrlSetState($ppass, $GUI_DISABLE)
				Else
					GUICtrlSetState($url, $GUI_ENABLE)
					GUICtrlSetState($prt, $GUI_ENABLE)
					GUICtrlSetState($puser, $GUI_ENABLE)
					GUICtrlSetState($ppass, $GUI_ENABLE)

				EndIf

			Case $botonSalir
				ExitLoop
		EndSwitch
	WEnd
	GUIDelete($config)
EndFunc   ;==>Settings

Func _proxy()
	Local $P_URL, $P_PRT, $P_USER, $P_PASS
	If $PROXY = 0 Then
		$P_URL = IniRead("updatevsd.ini", "PROXY", "P_URL", "")
		$P_PRT = IniRead("updatevsd.ini", "PROXY", "P_PRT", "")
		$P_USER = IniRead("updatevsd.ini", "PROXY", "P_USER", "")
		$P_PASS = IniRead("updatevsd.ini", "PROXY", "P_PASS", "")
		If $P_URL <> "" Or $P_PRT <> "" Then
			HttpSetProxy(2, $P_URL & ":" & $P_PRT, $P_USER, $P_PASS)
		Else
			HttpSetProxy(1)
		EndIf
	Else
		HttpSetProxy(0)
	EndIf
EndFunc   ;==>_proxy

;Funcion CRC32
Func _CRC32($sFile)

	Local $a_hCall = DllCall("kernel32.dll", "hwnd", "CreateFileW", _
			"wstr", $sFile, _
			"dword", 0x80000000, _ ; GENERIC_READ
			"dword", 3, _ ; FILE_SHARE_READ|FILE_SHARE_WRITE
			"ptr", 0, _
			"dword", 3, _ ; OPEN_EXISTING
			"dword", 0, _ ; SECURITY_ANONYMOUS
			"ptr", 0)

	If @error Or $a_hCall[0] = -1 Then
		Return SetError(1, 0, "")
	EndIf

	Local $hFile = $a_hCall[0]

	$a_hCall = DllCall("kernel32.dll", "ptr", "CreateFileMappingW", _
			"hwnd", $hFile, _
			"dword", 0, _ ; default security descriptor
			"dword", 2, _ ; PAGE_READONLY
			"dword", 0, _
			"dword", 0, _
			"ptr", 0)

	If @error Or Not $a_hCall[0] Then
		DllCall("kernel32.dll", "int", "CloseHandle", "hwnd", $hFile)
		Return SetError(2, 0, "")
	EndIf

	DllCall("kernel32.dll", "int", "CloseHandle", "hwnd", $hFile)

	Local $hFileMappingObject = $a_hCall[0]

	$a_hCall = DllCall("kernel32.dll", "ptr", "MapViewOfFile", _
			"hwnd", $hFileMappingObject, _
			"dword", 4, _ ; FILE_MAP_READ
			"dword", 0, _
			"dword", 0, _
			"dword", 0)

	If @error Or Not $a_hCall[0] Then
		DllCall("kernel32.dll", "int", "CloseHandle", "hwnd", $hFileMappingObject)
		Return SetError(3, 0, "")
	EndIf

	Local $pFile = $a_hCall[0]
	Local $iBufferSize = FileGetSize($sFile)

	Local $a_iCall = DllCall("ntdll.dll", "dword", "RtlComputeCrc32", _
			"dword", 0, _
			"ptr", $pFile, _
			"int", $iBufferSize)

	If @error Or Not $a_iCall[0] Then
		DllCall("kernel32.dll", "int", "UnmapViewOfFile", "ptr", $pFile)
		DllCall("kernel32.dll", "int", "CloseHandle", "hwnd", $hFileMappingObject)
		Return SetError(4, 0, "")
	EndIf

	DllCall("kernel32.dll", "int", "UnmapViewOfFile", "ptr", $pFile)
	DllCall("kernel32.dll", "int", "CloseHandle", "hwnd", $hFileMappingObject)

	Local $iCRC32 = $a_iCall[0]

	Return SetError(0, 0, Hex($iCRC32, 8))

EndFunc   ;==>_CRC32


Func _FileListToArray_Recursive($sPath, $sFilter = "*", $iRetItemType = 0, $iRetPathType = 0, $bRecursive = False)
	Local $sRet = "", $sRetPath = ""
	$sPath = StringRegExpReplace($sPath, "[\\/]+\z", "")
	If Not FileExists($sPath) Then Return SetError(1, 1, "")
	If StringRegExp($sFilter, "[\\/ :> <\|]|(?s)\A\s*\z") Then Return SetError(2, 2, "")
	$sPath &= "\|"
	$sOrigPathLen = StringLen($sPath) - 1
	While $sPath
		$sCurrPathLen = StringInStr($sPath, "|") - 1
		$sCurrPath = StringLeft($sPath, $sCurrPathLen)
		$Search = FileFindFirstFile($sCurrPath & $sFilter)
		If @error Then
			$sPath = StringTrimLeft($sPath, $sCurrPathLen + 1)
			ContinueLoop
		EndIf
		Switch $iRetPathType
			Case 1 ; relative path
				$sRetPath = StringTrimLeft($sCurrPath, $sOrigPathLen)
			Case 2 ; full path
				$sRetPath = $sCurrPath
		EndSwitch
		While 1
			$File = FileFindNextFile($Search)
			If @error Then ExitLoop
			If ($iRetItemType + @extended = 2) Then ContinueLoop
			$sRet &= $sRetPath & $File & "|"
		WEnd
		FileClose($Search)
		If $bRecursive Then
			$hSearch = FileFindFirstFile($sCurrPath & "*")
			While 1
				$File = FileFindNextFile($hSearch)
				If @error Then ExitLoop
				If @extended Then $sPath &= $sCurrPath & $File & "\|"
			WEnd
			FileClose($hSearch)
		EndIf
		$sPath = StringTrimLeft($sPath, $sCurrPathLen + 1)
	WEnd
	If Not $sRet Then Return SetError(4, 4, "")
	Return StringSplit(StringTrimRight($sRet, 1), "|")
EndFunc   ;==>_FileListToArray_Recursive

Func _history()

	Local $Line
	Local $FileLog = FileOpen("updatevsd.log", 0)

	If $FileLog = -1 Then
		_ConsoleAlloc()
		_ConsoleWrite(@CRLF)
		_ConsoleWrite("================ History ================" & @CRLF)
		_ConsoleWrite(@CRLF)
		_ConsoleWrite("-- Record was not found." & @CRLF)
		_ConsoleWrite(@CRLF)
		_ConsoleWrite("================== End =================" & @CRLF)
		_ConsoleWrite(@CRLF)
		_ConsolePause()
		_ConsoleFree()
		Exit
	EndIf
	_ConsoleAlloc()
	_ConsoleWrite(@CRLF)
	_ConsoleWrite("================ History ================" & @CRLF)
	While 1
		Local $Line = FileReadLine($FileLog)
		If @error = -1 Then ExitLoop
		_ConsoleWrite($Line & @CRLF)
	WEnd

	FileClose($FileLog)
	_ConsoleWrite(@CRLF)
	_ConsoleWrite("================== End =================" & @CRLF)
	_ConsoleWrite(@CRLF)
	_ConsolePause()
	_ConsoleFree()

EndFunc   ;==>_history

Func _help()

	_ConsoleAlloc()
	_ConsoleWrite(@CRLF)
	_ConsoleWrite("UpdateVSD is a tool to update files from Virtual Section Dumper." & @CRLF)
	_ConsoleWrite(@CRLF)
	_ConsoleWrite("Usage: updatevsd.exe [Commands]" & @CRLF & @CRLF)
	_ConsoleWrite("Commands:" & @CRLF)
	_ConsoleWrite("/help - Shows this help (/? /help /h -help --help -h)" & @CRLF)
	_ConsoleWrite("/settings - Shows proxy configuration" & @CRLF)
	_ConsoleWrite("/history - Shows history update" & @CRLF)
	_ConsoleWrite(@CRLF)
	_ConsolePause()
	_ConsoleFree()

EndFunc   ;==>_help

Func _ConsoleWrite($text, $Unicode = Default, $Dll = -1)
	Return _ConsoleWriteConsole(-1, $text, $Unicode, $Dll)
EndFunc   ;==>_ConsoleWrite

Func _ConsoleWriteConsole($Console, $text, $Unicode = Default, $Dll = -1)
	Local $Result

	If $Unicode = Default Then $Unicode = True
	If $Dll = -1 Then $Dll = "kernel32.dll"
	If $Console = -1 Then $Console = _ConsoleGetHandle(-11, $Dll)

	If $Unicode Then
		$Result = DllCall($Dll, "bool", "WriteConsoleW", _
				"handle", $Console, _
				"wstr", $text, _
				"dword", StringLen($text), _
				"dword*", 0, _
				"ptr", 0)
	Else
		$Result = DllCall($Dll, "bool", "WriteConsoleA", _
				"handle", $Console, _
				"str", $text, _
				"dword", StringLen($text), _
				"dword*", 0, _
				"ptr", 0)
	EndIf
	If @error Then Return SetError(@error, @extended, False)

	Return SetExtended($Result[4], $Result[0] <> 0)
EndFunc   ;==>_ConsoleWriteConsole

Func _ConsoleGetHandle($Handle = -11, $Dll = -1)
	Local $Result

	If $Dll = -1 Then $Dll = "kernel32.dll"

	$Result = DllCall($Dll, "handle", "GetStdHandle", _
			"dword", $Handle)
	If @error Then Return SetError(@error, @extended, 0)

	Return $Result[0]
EndFunc   ;==>_ConsoleGetHandle

Func _ConsoleAlloc($Dll = -1)
	Local $Result

	If $Dll = -1 Then $Dll = "kernel32.dll"

	$Result = DllCall($Dll, "bool", "AllocConsole")
	If @error Then Return SetError(@error, @extended, 0)

	Return $Result[0] <> 0
EndFunc   ;==>_ConsoleAlloc

Func _ConsolePause($Message = Default, $Dll = -1)
	If $Message = Default Then
		RunWait(@ComSpec & " /c PAUSE", @ScriptDir, Default, 0x10)
	Else
		_ConsoleWrite($Message, $Dll)
		RunWait(@ComSpec & " /c PAUSE >nul", @ScriptDir, Default, 0x10)
	EndIf
EndFunc   ;==>_ConsolePause

Func _ConsoleFree($Dll = -1)
	Local $Result

	If $Dll = -1 Then $Dll = "kernel32.dll"

	$Result = DllCall($Dll, "bool", "FreeConsole")
	If @error Then Return SetError(@error, @extended, False)

	Return $Result[0] <> 0
EndFunc   ;==>_ConsoleFree

