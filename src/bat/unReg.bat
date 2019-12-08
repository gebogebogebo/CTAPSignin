cd /d %~dp0

rem  set __COMPAT_LAYER=RunAsInvoker  
REGEDIT.EXE  /S "..\CredentialProviderCTAP\Unregister.reg"
 
pause

