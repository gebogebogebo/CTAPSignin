cd /d %~dp0

copy "..\CredentialProviderCTAP\x64\Release\CredentialProviderCTAP.dll" "C:\Windows\System32"

rem  set __COMPAT_LAYER=RunAsInvoker  
REGEDIT.EXE  /S "..\CredentialProviderCTAP\register.reg"

pause

