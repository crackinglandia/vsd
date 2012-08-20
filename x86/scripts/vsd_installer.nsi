; $Id$

;VSD 2.0 x86 Installer
;Written by +NCR/CRC! [ReVeRsEr]

  !include "MUI2.nsh"

  Name "VSD v2.0 x86"
  OutFile "VSD-2.0-x86-setup.exe"
  BrandingText "Virtual Section Dumper v2.0 x86 - crackinglandia"
  CRCCheck on
  XPStyle  on
 
  ;Default installation folder
  InstallDir "$PROGRAMFILES\VSD v2.0 x86"
 
  ;Get installation folder from registry if available
  InstallDirRegKey HKCU "Software\VSD2" ""

  ;Request application privileges for Windows Vista
  RequestExecutionLevel admin

  !define MUI_ABORTWARNING

  !define MUI_LANGDLL_REGISTRY_ROOT "HKCU"
  !define MUI_LANGDLL_REGISTRY_KEY "Software\VSD2"
  !define MUI_LANGDLL_REGISTRY_VALUENAME "Installer Language"

  !insertmacro MUI_PAGE_LICENSE "C:\VSD v2.0 x86\LICENSE"
  !insertmacro MUI_PAGE_COMPONENTS
  !insertmacro MUI_PAGE_DIRECTORY
  !insertmacro MUI_PAGE_INSTFILES
 
  !insertmacro MUI_UNPAGE_CONFIRM
  !insertmacro MUI_UNPAGE_INSTFILES

  !insertmacro MUI_LANGUAGE "English" ;first language is the default language
  !insertmacro MUI_LANGUAGE "French"
  !insertmacro MUI_LANGUAGE "German"
  !insertmacro MUI_LANGUAGE "Spanish"
  !insertmacro MUI_LANGUAGE "SpanishInternational"
  !insertmacro MUI_LANGUAGE "SimpChinese"
  !insertmacro MUI_LANGUAGE "TradChinese"
  !insertmacro MUI_LANGUAGE "Japanese"
  !insertmacro MUI_LANGUAGE "Korean"
  !insertmacro MUI_LANGUAGE "Italian"
  !insertmacro MUI_LANGUAGE "Dutch"
  !insertmacro MUI_LANGUAGE "Danish"
  !insertmacro MUI_LANGUAGE "Swedish"
  !insertmacro MUI_LANGUAGE "Norwegian"
  !insertmacro MUI_LANGUAGE "NorwegianNynorsk"
  !insertmacro MUI_LANGUAGE "Finnish"
  !insertmacro MUI_LANGUAGE "Greek"
  !insertmacro MUI_LANGUAGE "Russian"
  !insertmacro MUI_LANGUAGE "Portuguese"
  !insertmacro MUI_LANGUAGE "PortugueseBR"
  !insertmacro MUI_LANGUAGE "Polish"
  !insertmacro MUI_LANGUAGE "Ukrainian"
  !insertmacro MUI_LANGUAGE "Czech"
  !insertmacro MUI_LANGUAGE "Slovak"
  !insertmacro MUI_LANGUAGE "Croatian"
  !insertmacro MUI_LANGUAGE "Bulgarian"
  !insertmacro MUI_LANGUAGE "Hungarian"
  !insertmacro MUI_LANGUAGE "Thai"
  !insertmacro MUI_LANGUAGE "Romanian"
  !insertmacro MUI_LANGUAGE "Latvian"
  !insertmacro MUI_LANGUAGE "Macedonian"
  !insertmacro MUI_LANGUAGE "Estonian"
  !insertmacro MUI_LANGUAGE "Turkish"
  !insertmacro MUI_LANGUAGE "Lithuanian"
  !insertmacro MUI_LANGUAGE "Slovenian"
  !insertmacro MUI_LANGUAGE "Serbian"
  !insertmacro MUI_LANGUAGE "SerbianLatin"
  !insertmacro MUI_LANGUAGE "Arabic"
  !insertmacro MUI_LANGUAGE "Farsi"
  !insertmacro MUI_LANGUAGE "Hebrew"
  !insertmacro MUI_LANGUAGE "Indonesian"
  !insertmacro MUI_LANGUAGE "Mongolian"
  !insertmacro MUI_LANGUAGE "Luxembourgish"
  !insertmacro MUI_LANGUAGE "Albanian"
  !insertmacro MUI_LANGUAGE "Breton"
  !insertmacro MUI_LANGUAGE "Belarusian"
  !insertmacro MUI_LANGUAGE "Icelandic"
  !insertmacro MUI_LANGUAGE "Malay"
  !insertmacro MUI_LANGUAGE "Bosnian"
  !insertmacro MUI_LANGUAGE "Kurdish"
  !insertmacro MUI_LANGUAGE "Irish"
  !insertmacro MUI_LANGUAGE "Uzbek"
  !insertmacro MUI_LANGUAGE "Galician"
  !insertmacro MUI_LANGUAGE "Afrikaans"
  !insertmacro MUI_LANGUAGE "Catalan"
  !insertmacro MUI_LANGUAGE "Esperanto"
 
  !insertmacro MUI_RESERVEFILE_LANGDLL

Section "VSD v2.0 x86" MainVSDFiles

  SetOutPath "$INSTDIR\"
 
  CreateDirectory "$SMPROGRAMS\VSD v2.0 x86"
  CreateShortCut "$SMPROGRAMS\VSD v2.0 x86\VSD v2.0 x86.lnk" \
                 "$INSTDIR\vsd_win32.exe"
 
  CreateShortCut "$SMPROGRAMS\VSD v2.0 x86\Uninstall VSD v2.0 x86.lnk" \
                 "$INSTDIR\uninstall.exe"

  CreateShortCut "$SMPROGRAMS\VSD v2.0 x86\Readme.lnk" \
                 "$INSTDIR\readme.txt"

  CreateShortCut "$SMPROGRAMS\VSD v2.0 x86\Changelog.lnk" \
                 "$INSTDIR\changelog.txt"

  CreateShortCut "$SMPROGRAMS\VSD v2.0 x86\LICENSE.lnk" \
                 "$INSTDIR\LICENSE"
				 
  File vsd_win32.exe

  ;Store installation folder
  WriteRegStr HKCU "Software\VSD2" "" $INSTDIR
 
  ;Create uninstaller
  WriteUninstaller "$INSTDIR\Uninstall.exe"

  SetOutPath "$INSTDIR"
 
  File changelog.txt
  File readme.txt
  File LICENSE
 
  Exec "explorer $SMPROGRAMS\VSD v2.0 x86\"
SectionEnd

Function .onInit

  !insertmacro MUI_LANGDLL_DISPLAY

FunctionEnd

  !insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
    !insertmacro MUI_DESCRIPTION_TEXT ${MainVSDFiles} "VSD v2.0 x86 files"
  !insertmacro MUI_FUNCTION_DESCRIPTION_END

Section "Uninstall"

  RMDir /r "$SMPROGRAMS\VSD v2.0 x86"
  RMDir /r "$INSTDIR"

  Delete "$INSTDIR\Uninstall.exe"

  RMDir "$INSTDIR"

  DeleteRegKey /ifempty HKCU "Software\VSD2"

SectionEnd

Function un.onInit

  !insertmacro MUI_UNGETLANGUAGE
 
FunctionEnd


