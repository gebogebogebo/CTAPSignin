//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.
//
//

#ifndef WIN32_NO_STATUS
#include <ntstatus.h>
#define WIN32_NO_STATUS
#endif
#include <unknwn.h>
#include "CSampleCredential.h"
#include "guid.h"

extern wchar_t	DebugLogBuff[512];

CSampleCredential::CSampleCredential():
    _cRef(1),
    _pCredProvCredentialEvents(nullptr),
    _pszUserSid(nullptr),
    _pszQualifiedUserName(nullptr),
    _fIsLocalUser(false),
    _fChecked(false),
    //_fShowControls(false),
    _dwComboIndex(0)
{
	OutLog(L"CSampleCredential::CSampleCredential() - in");

    DllAddRef();

    ZeroMemory(_rgCredProvFieldDescriptors, sizeof(_rgCredProvFieldDescriptors));
    ZeroMemory(_rgFieldStatePairs, sizeof(_rgFieldStatePairs));
    ZeroMemory(_rgFieldStrings, sizeof(_rgFieldStrings));
	ZeroMemory(_userName, sizeof(_userName));
	OutLog(L"CSampleCredential::CSampleCredential() - out");
}

CSampleCredential::~CSampleCredential()
{
	OutLog(L"CSampleCredential::~CSampleCredential() - in");

    if (_rgFieldStrings[SFI_PASSWORD])
    {
        size_t lenPassword = wcslen(_rgFieldStrings[SFI_PASSWORD]);
        SecureZeroMemory(_rgFieldStrings[SFI_PASSWORD], lenPassword * sizeof(*_rgFieldStrings[SFI_PASSWORD]));
    }
    for (int i = 0; i < ARRAYSIZE(_rgFieldStrings); i++)
    {
        CoTaskMemFree(_rgFieldStrings[i]);
        CoTaskMemFree(_rgCredProvFieldDescriptors[i].pszLabel);
    }
    CoTaskMemFree(_pszUserSid);
    CoTaskMemFree(_pszQualifiedUserName);
    DllRelease();

	OutLog(L"CSampleCredential::~CSampleCredential() - out");
}


// Initializes one credential with the field information passed in.
// Set the value of the SFI_LARGE_TEXT field to pwzUsername.
HRESULT CSampleCredential::Initialize(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                                      _In_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR const	*rgcpfd,	// (I )コントロール定義
                                      _In_ FIELD_STATE_PAIR	const						*rgfsp,		// (I )コントロールのステータス
                                      _In_ ICredentialProviderUser						*pcpUser	// (I )ユーザー情報
										)
{
	OutLog(L"CSampleCredential::Initialize() - in");

    HRESULT hr = S_OK;
    _cpus = cpus;

    GUID guidProvider;
    pcpUser->GetProviderID(&guidProvider);
    _fIsLocalUser = (guidProvider == Identity_LocalUserProvider);

    // Copy the field descriptors for each field. This is useful if you want to vary the field
    // descriptors based on what Usage scenario the credential was created for.
    for (DWORD i = 0; SUCCEEDED(hr) && i < ARRAYSIZE(_rgCredProvFieldDescriptors); i++)
    {
		// _rgFieldStatePairs に保存
        _rgFieldStatePairs[i] = rgfsp[i];
		// _rgCredProvFieldDescriptors に保存
        hr = FieldDescriptorCopy(rgcpfd[i], &_rgCredProvFieldDescriptors[i]);
    }

    // Initialize the String value of all the fields.
    if (SUCCEEDED(hr))
    {
		// _rgFieldStrings に "Sample Credential" と設定する
        hr = SHStrDupW(L"Sample Credential", &_rgFieldStrings[SFI_LABEL]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"FIDO Key Sign-in", &_rgFieldStrings[SFI_LARGE_TEXT]);
    }
	if (SUCCEEDED(hr))
	{
		hr = SHStrDupW(L"", &_rgFieldStrings[SFI_EDIT_TEXT]);
	}
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PASSWORD]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Submit", &_rgFieldStrings[SFI_SUBMIT_BUTTON]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_CHECKBOX]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_COMBOBOX]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Authenticate", &_rgFieldStrings[SFI_LAUNCHWINDOW_LINK]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Hide additional controls", &_rgFieldStrings[SFI_HIDECONTROLS_LINK]);
    }
    if (SUCCEEDED(hr))
    {
        hr = pcpUser->GetStringValue(PKEY_Identity_QualifiedUserName, &_pszQualifiedUserName);
    }
    if (SUCCEEDED(hr))
    {
		hr = SHStrDupW(L"", &_rgFieldStrings[SFI_FULLNAME_TEXT]);

		// UserNameを取得
        PWSTR pszUserName;
        pcpUser->GetStringValue(PKEY_Identity_UserName, &pszUserName);
		if (pszUserName != nullptr) {
			wcscpy_s(_userName, 256, pszUserName);
            CoTaskMemFree(pszUserName);
        }
	}

    if (SUCCEEDED(hr))
    {
		hr = SHStrDupW(L"", &_rgFieldStrings[SFI_DISPLAYNAME_TEXT]);
	}

    if (SUCCEEDED(hr))
    {
		hr = SHStrDupW(L"", &_rgFieldStrings[SFI_LOGONSTATUS_TEXT]);
	}

    if (SUCCEEDED(hr))
    {
        hr = pcpUser->GetSid(&_pszUserSid);
    }

	OutLog(L"CSampleCredential::Initialize() - out");
	return hr;
}

// LogonUI calls this in order to give us a callback in case we need to notify it of anything.
HRESULT CSampleCredential::Advise(_In_ ICredentialProviderCredentialEvents *pcpce)
{
    if (_pCredProvCredentialEvents != nullptr)
    {
        _pCredProvCredentialEvents->Release();
    }
    return pcpce->QueryInterface(IID_PPV_ARGS(&_pCredProvCredentialEvents));
}

// LogonUI calls this to tell us to release the callback.
HRESULT CSampleCredential::UnAdvise()
{
    if (_pCredProvCredentialEvents)
    {
        _pCredProvCredentialEvents->Release();
    }
    _pCredProvCredentialEvents = nullptr;
    return S_OK;
}

// LogonUI calls this function when our tile is selected (zoomed)
// If you simply want fields to show/hide based on the selected state,
// there's no need to do anything here - you can set that up in the
// field definitions. But if you want to do something
// more complicated, like change the contents of a field when the tile is
// selected, you would do it here.
HRESULT CSampleCredential::SetSelected(_Out_ BOOL *pbAutoLogon)
{
    *pbAutoLogon = FALSE;
    return S_OK;
}

// Similarly to SetSelected, LogonUI calls this when your tile was selected
// and now no longer is. The most common thing to do here (which we do below)
// is to clear out the password field.
HRESULT CSampleCredential::SetDeselected()
{
    HRESULT hr = S_OK;
    if (_rgFieldStrings[SFI_PASSWORD])
    {
        size_t lenPassword = wcslen(_rgFieldStrings[SFI_PASSWORD]);
        SecureZeroMemory(_rgFieldStrings[SFI_PASSWORD], lenPassword * sizeof(*_rgFieldStrings[SFI_PASSWORD]));

        CoTaskMemFree(_rgFieldStrings[SFI_PASSWORD]);
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PASSWORD]);

        if (SUCCEEDED(hr) && _pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->SetFieldString(this, SFI_PASSWORD, _rgFieldStrings[SFI_PASSWORD]);
        }
    }

    return hr;
}

// Get info for a particular field of a tile. Called by logonUI to get information
// to display the tile.
HRESULT CSampleCredential::GetFieldState(DWORD dwFieldID,
                                         _Out_ CREDENTIAL_PROVIDER_FIELD_STATE *pcpfs,
                                         _Out_ CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE *pcpfis)
{
    HRESULT hr;

    // Validate our parameters.
    if ((dwFieldID < ARRAYSIZE(_rgFieldStatePairs)))
    {
        *pcpfs = _rgFieldStatePairs[dwFieldID].cpfs;
        *pcpfis = _rgFieldStatePairs[dwFieldID].cpfis;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

// Sets ppwsz to the string value of the field at the index dwFieldID
HRESULT CSampleCredential::GetStringValue(DWORD dwFieldID, _Outptr_result_nullonfailure_ PWSTR *ppwsz)
{
    HRESULT hr;
    *ppwsz = nullptr;

    // Check to make sure dwFieldID is a legitimate index
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors))
    {
        // Make a copy of the string and return that. The caller
        // is responsible for freeing it.
        hr = SHStrDupW(_rgFieldStrings[dwFieldID], ppwsz);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Get the image to show in the user tile
HRESULT CSampleCredential::GetBitmapValue(DWORD dwFieldID, _Outptr_result_nullonfailure_ HBITMAP *phbmp)
{
    HRESULT hr;
    *phbmp = nullptr;

    if ((SFI_TILEIMAGE == dwFieldID))
    {
        HBITMAP hbmp = LoadBitmap(HINST_THISDLL, MAKEINTRESOURCE(IDB_TILE_IMAGE));
        if (hbmp != nullptr)
        {
            hr = S_OK;
            *phbmp = hbmp;
        }
        else
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
        }
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Sets pdwAdjacentTo to the index of the field the submit button should be
// adjacent to. We recommend that the submit button is placed next to the last
// field which the user is required to enter information in. Optional fields
// should be below the submit button.
HRESULT CSampleCredential::GetSubmitButtonValue(DWORD dwFieldID, _Out_ DWORD *pdwAdjacentTo)
{
    HRESULT hr;

    if (SFI_SUBMIT_BUTTON == dwFieldID)
    {
        // pdwAdjacentTo is a pointer to the fieldID you want the submit button to
        // appear next to.
        *pdwAdjacentTo = SFI_PASSWORD;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

// Sets the value of a field which can accept a string as a value.
// This is called on each keystroke when a user types into an edit field
HRESULT CSampleCredential::SetStringValue(DWORD dwFieldID, _In_ PCWSTR pwz)
{
    HRESULT hr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_EDIT_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft ||
        CPFT_PASSWORD_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        PWSTR *ppwszStored = &_rgFieldStrings[dwFieldID];
        CoTaskMemFree(*ppwszStored);
        hr = SHStrDupW(pwz, ppwszStored);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

HRESULT CSampleCredential::GetCheckboxValue(DWORD dwFieldID, _Out_ BOOL *pbChecked, _Outptr_result_nullonfailure_ PWSTR *ppwszLabel)
{
	*ppwszLabel = nullptr;
	return E_INVALIDARG;
}

HRESULT CSampleCredential::SetCheckboxValue(DWORD dwFieldID, BOOL bChecked)
{
	return E_INVALIDARG;
}

HRESULT CSampleCredential::GetComboBoxValueCount(DWORD dwFieldID, _Out_ DWORD *pcItems, _Deref_out_range_(<, *pcItems) _Out_ DWORD *pdwSelectedItem)
{
	*pcItems = 0;
	*pdwSelectedItem = 0;
	return(E_INVALIDARG);
}

HRESULT CSampleCredential::GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, _Outptr_result_nullonfailure_ PWSTR *ppwszItem)
{
	*ppwszItem = nullptr;
	return E_INVALIDARG;
}

HRESULT CSampleCredential::SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem)
{
	return E_INVALIDARG;
}

static wchar_t LoginPass[256];
// Called when the user clicks a command link.
HRESULT CSampleCredential::CommandLinkClicked(DWORD dwFieldID)
{
	OutLog(L"CSampleCredential::CommandLinkClicked - in");

    HRESULT hr = S_OK;

    CREDENTIAL_PROVIDER_FIELD_STATE cpfsShow = CPFS_HIDDEN;

    // Validate parameter.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_COMMAND_LINK == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        HWND hwndOwner = nullptr;
        switch (dwFieldID)
        {
        case SFI_LAUNCHWINDOW_LINK:
			OutLog(L"Process Kick");
			if (_pCredProvCredentialEvents)
            {
                _pCredProvCredentialEvents->OnCreatingWindow(&hwndOwner);
            }

			{
				swprintf(DebugLogBuff, 512, L"- Current User = %s", _userName);
				OutLog(DebugLogBuff);
			}

			// PEND Kick
			{
				//ワイド文字列(WCHAR*)をマルチバイト文字列(char*)に変換
				//変換文字列格納バッファ
				char	wStrC[256];

				size_t wLen = 0;
				errno_t err = 0;

				//変換
				err = wcstombs_s(&wLen, wStrC, 256, _userName, _TRUNCATE);

				char exec[256];
				sprintf_s(exec, 256, "C:\\CTAPSignIn\\bin\\CTAPget.exe %s", wStrC);
				WinExec(exec, SW_SHOW);
			}

			// 終了まで待機する
			wchar_t _password[256];
			{
				_password[0] = L'\0';
				BOOL	getpass = FALSE;

				OutLog(L"Wait - Start");
				for (int intIc = 0;intIc < 30;intIc++) {
					swprintf_s(DebugLogBuff,512, L"- Wait=%d", intIc);
					OutLog(DebugLogBuff);

					getpass = this->_PollData(_password);
					if (getpass == TRUE) {
						swprintf_s(DebugLogBuff,512,L"- get password=%s", _password);
						OutLog(DebugLogBuff);
						break;
					}

					Sleep(1000);
				}
				OutLog(L"Wait - End");
			}
			if (wcslen(_password) <= 0) {
				OutLog(L"No Password");
				return(E_INVALIDARG);
			}

			// パスワードを設定
			wcscpy_s(LoginPass, 256, _password);
			swprintf_s(DebugLogBuff,512, L"- LoginPass 1 =%s", LoginPass);
			OutLog(DebugLogBuff);

			_pCredProvCredentialEvents->SetFieldString(this, SFI_PASSWORD, LoginPass);

			swprintf_s(DebugLogBuff,512, L"- LoginPass 2 =%s", LoginPass);
			OutLog(DebugLogBuff);

			Sleep(1000);

			// Sift+TAB
			{
				INPUT input[4];

				input[0].type = INPUT_KEYBOARD;
				input[0].ki.wScan = MapVirtualKey(VK_SHIFT, 0);
				input[0].ki.time = 0;
				input[0].ki.dwExtraInfo = GetMessageExtraInfo();
				input[0].ki.wVk = VK_SHIFT;
				input[0].ki.dwFlags = KEYEVENTF_EXTENDEDKEY;

				input[1].type = INPUT_KEYBOARD;
				input[1].ki.wScan = MapVirtualKey(VK_TAB, 0);
				input[1].ki.time = 0;
				input[1].ki.dwExtraInfo = GetMessageExtraInfo();
				input[1].ki.wVk = VK_TAB;
				input[1].ki.dwFlags = KEYEVENTF_EXTENDEDKEY;

				input[2].type = INPUT_KEYBOARD;
				input[2].ki.wScan = MapVirtualKey(VK_TAB, 0);
				input[2].ki.time = 0;
				input[2].ki.dwExtraInfo = GetMessageExtraInfo();
				input[2].ki.wVk = VK_TAB;
				input[2].ki.dwFlags = KEYEVENTF_EXTENDEDKEY | KEYEVENTF_KEYUP;

				input[3].type = INPUT_KEYBOARD;
				input[3].ki.wScan = MapVirtualKey(VK_SHIFT, 0);
				input[3].ki.time = 0;
				input[3].ki.dwExtraInfo = GetMessageExtraInfo();
				input[3].ki.wVk = VK_SHIFT;
				input[3].ki.dwFlags = KEYEVENTF_EXTENDEDKEY | KEYEVENTF_KEYUP;

				SendInput(4, input, sizeof(INPUT));
			}

			{
				INPUT input[2];

				input[0].type = INPUT_KEYBOARD;
				input[0].ki.wScan = MapVirtualKey(VK_RETURN, 0);
				input[0].ki.time = 0;
				input[0].ki.dwExtraInfo = GetMessageExtraInfo();
				input[0].ki.wVk = VK_RETURN;
				input[0].ki.dwFlags = KEYEVENTF_EXTENDEDKEY;

				input[1].type = INPUT_KEYBOARD;
				input[1].ki.wScan = MapVirtualKey(VK_RETURN, 0);
				input[1].ki.time = 0;
				input[1].ki.dwExtraInfo = GetMessageExtraInfo();
				input[1].ki.wVk = VK_RETURN;
				input[1].ki.dwFlags = KEYEVENTF_EXTENDEDKEY | KEYEVENTF_KEYUP;

				SendInput(2, input, sizeof(INPUT));
			}

            break;
        default:
            hr = E_INVALIDARG;
        }

    }
    else
    {
        hr = E_INVALIDARG;
    }
	OutLog(L"CSampleCredential::CommandLinkClicked - out");

    return hr;
}


BOOL CSampleCredential::_PollData(wchar_t* password)
{
	HANDLE pipeHandle = NULL;
	password[0] = L'\0';

	//OutLog("- Create Pipe");
	{
		pipeHandle = CreateFile(L"\\\\.\\pipe\\ctapgetpipe", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
		if (pipeHandle == INVALID_HANDLE_VALUE) {
			//OutLog("- Error Create Pipe");
			return FALSE;
		}
	}
	OutLog(L"- Success Create Pipe");

	{
		// 文字列受信
		char tmp[256];    //受信バッファ
		wchar_t recvBuffer[256];    //受信バッファ

		recvBuffer[0] = L'\0';
		DWORD readBytes = 0;
		BOOL readst = ReadFile(pipeHandle, (LPVOID)tmp, sizeof(tmp), &readBytes, NULL);
		if (readst == FALSE || readBytes == 0 || tmp[0] == '\0') {
			OutLog(L"- ReadFile Error");
			CloseHandle(pipeHandle);
			// ここでもTRUEで返してしまう
			return TRUE;
		}
		{
			swprintf_s(DebugLogBuff, 512, L"- readBytes=%d", readBytes);
			OutLog(DebugLogBuff);
		}

		tmp[readBytes] = '\0';
		OutLog(L"- Receive");

		// wchar_t は 2byte
		size_t wLen = 0;
		errno_t err = 0;
		err = mbstowcs_s(&wLen, recvBuffer, 256, tmp, _TRUNCATE);

		CloseHandle(pipeHandle);
		OutLog(L"- Handle Closed");

		{
			swprintf(DebugLogBuff,512, L"- recvBuffer=%s", recvBuffer);
			OutLog(DebugLogBuff);
		}

		wcscpy_s(password,256,recvBuffer);

		{
			swprintf_s(DebugLogBuff,512, L"- password=%s", password);
			OutLog(DebugLogBuff);
		}
	}

	return TRUE;
}



// Collect the username and password into a serialized credential for the correct usage scenario
// (logon/unlock is what's demonstrated in this sample).  LogonUI then passes these credentials
// back to the system to log on.
// 正しい使用シナリオのために、
// ユーザー名とパスワードをシリアル化された資格情報に収集します
//（ログオン/ロック解除はこのサンプルで示されています）。
// LogonUIは、これらの資格情報をシステムに戻してログオンします。
HRESULT CSampleCredential::GetSerialization(_Out_ CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE *pcpgsr,
                                            _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *pcpcs,
                                            _Outptr_result_maybenull_ PWSTR *ppwszOptionalStatusText,
                                            _Out_ CREDENTIAL_PROVIDER_STATUS_ICON *pcpsiOptionalStatusIcon)
{
    HRESULT hr = E_UNEXPECTED;
    *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
    *ppwszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;
    ZeroMemory(pcpcs, sizeof(*pcpcs));

    // For local user, the domain and user name can be split from _pszQualifiedUserName (domain\username).
    // CredPackAuthenticationBuffer() cannot be used because it won't work with unlock scenario.
    if (_fIsLocalUser)
    {
        PWSTR pwzProtectedPassword;
        hr = ProtectIfNecessaryAndCopyPassword(_rgFieldStrings[SFI_PASSWORD], _cpus, &pwzProtectedPassword);
        if (SUCCEEDED(hr))
        {
            PWSTR pszDomain;
            PWSTR pszUsername;
            hr = SplitDomainAndUsername(_pszQualifiedUserName, &pszDomain, &pszUsername);
            if (SUCCEEDED(hr))
            {
                KERB_INTERACTIVE_UNLOCK_LOGON kiul;
                hr = KerbInteractiveUnlockLogonInit(pszDomain, pszUsername, pwzProtectedPassword, _cpus, &kiul);
                if (SUCCEEDED(hr))
                {
                    // We use KERB_INTERACTIVE_UNLOCK_LOGON in both unlock and logon scenarios.  It contains a
                    // KERB_INTERACTIVE_LOGON to hold the creds plus a LUID that is filled in for us by Winlogon
                    // as necessary.
                    hr = KerbInteractiveUnlockLogonPack(kiul, &pcpcs->rgbSerialization, &pcpcs->cbSerialization);
                    if (SUCCEEDED(hr))
                    {
                        ULONG ulAuthPackage;
                        hr = RetrieveNegotiateAuthPackage(&ulAuthPackage);
                        if (SUCCEEDED(hr))
                        {
                            pcpcs->ulAuthenticationPackage = ulAuthPackage;
                            pcpcs->clsidCredentialProvider = CLSID_CSample;
                            // At this point the credential has created the serialized credential used for logon
                            // By setting this to CPGSR_RETURN_CREDENTIAL_FINISHED we are letting logonUI know
                            // that we have all the information we need and it should attempt to submit the
                            // serialized credential.
                            *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
                        }
                    }
                }
                CoTaskMemFree(pszDomain);
                CoTaskMemFree(pszUsername);
            }
            CoTaskMemFree(pwzProtectedPassword);
        }
    }
    else
    {
        DWORD dwAuthFlags = CRED_PACK_PROTECTED_CREDENTIALS | CRED_PACK_ID_PROVIDER_CREDENTIALS;

        // First get the size of the authentication buffer to allocate
        if (!CredPackAuthenticationBuffer(dwAuthFlags, _pszQualifiedUserName, const_cast<PWSTR>(_rgFieldStrings[SFI_PASSWORD]), nullptr, &pcpcs->cbSerialization) &&
            (GetLastError() == ERROR_INSUFFICIENT_BUFFER))
        {
            pcpcs->rgbSerialization = static_cast<byte *>(CoTaskMemAlloc(pcpcs->cbSerialization));
            if (pcpcs->rgbSerialization != nullptr)
            {
                hr = S_OK;

                // Retrieve the authentication buffer
                if (CredPackAuthenticationBuffer(dwAuthFlags, _pszQualifiedUserName, const_cast<PWSTR>(_rgFieldStrings[SFI_PASSWORD]), pcpcs->rgbSerialization, &pcpcs->cbSerialization))
                {
                    ULONG ulAuthPackage;
                    hr = RetrieveNegotiateAuthPackage(&ulAuthPackage);
                    if (SUCCEEDED(hr))
                    {
                        pcpcs->ulAuthenticationPackage = ulAuthPackage;
                        pcpcs->clsidCredentialProvider = CLSID_CSample;

                        // At this point the credential has created the serialized credential used for logon
                        // By setting this to CPGSR_RETURN_CREDENTIAL_FINISHED we are letting logonUI know
                        // that we have all the information we need and it should attempt to submit the
                        // serialized credential.
                        *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
                    }
                }
                else
                {
                    hr = HRESULT_FROM_WIN32(GetLastError());
                    if (SUCCEEDED(hr))
                    {
                        hr = E_FAIL;
                    }
                }

                if (FAILED(hr))
                {
                    CoTaskMemFree(pcpcs->rgbSerialization);
                }
            }
            else
            {
                hr = E_OUTOFMEMORY;
            }
        }
    }
    return hr;
}

struct REPORT_RESULT_STATUS_INFO
{
    NTSTATUS ntsStatus;
    NTSTATUS ntsSubstatus;
    PWSTR     pwzMessage;
    CREDENTIAL_PROVIDER_STATUS_ICON cpsi;
};

static const REPORT_RESULT_STATUS_INFO s_rgLogonStatusInfo[] =
{
    { STATUS_LOGON_FAILURE, STATUS_SUCCESS, L"Incorrect password or username.", CPSI_ERROR, },
    { STATUS_ACCOUNT_RESTRICTION, STATUS_ACCOUNT_DISABLED, L"The account is disabled.", CPSI_WARNING },
};

// ReportResult is completely optional.  Its purpose is to allow a credential to customize the string
// and the icon displayed in the case of a logon failure.  For example, we have chosen to
// customize the error shown in the case of bad username/password and in the case of the account
// being disabled.
HRESULT CSampleCredential::ReportResult(NTSTATUS ntsStatus,
                                        NTSTATUS ntsSubstatus,
                                        _Outptr_result_maybenull_ PWSTR *ppwszOptionalStatusText,
                                        _Out_ CREDENTIAL_PROVIDER_STATUS_ICON *pcpsiOptionalStatusIcon)
{
    *ppwszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;

    DWORD dwStatusInfo = (DWORD)-1;

    // Look for a match on status and substatus.
    for (DWORD i = 0; i < ARRAYSIZE(s_rgLogonStatusInfo); i++)
    {
        if (s_rgLogonStatusInfo[i].ntsStatus == ntsStatus && s_rgLogonStatusInfo[i].ntsSubstatus == ntsSubstatus)
        {
            dwStatusInfo = i;
            break;
        }
    }

    if ((DWORD)-1 != dwStatusInfo)
    {
        if (SUCCEEDED(SHStrDupW(s_rgLogonStatusInfo[dwStatusInfo].pwzMessage, ppwszOptionalStatusText)))
        {
            *pcpsiOptionalStatusIcon = s_rgLogonStatusInfo[dwStatusInfo].cpsi;
        }
    }

    // If we failed the logon, try to erase the password field.
    if (FAILED(HRESULT_FROM_NT(ntsStatus)))
    {
        if (_pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->SetFieldString(this, SFI_PASSWORD, L"");
        }
    }

    // Since nullptr is a valid value for *ppwszOptionalStatusText and *pcpsiOptionalStatusIcon
    // this function can't fail.
    return S_OK;
}

// Gets the SID of the user corresponding to the credential.
HRESULT CSampleCredential::GetUserSid(_Outptr_result_nullonfailure_ PWSTR *ppszSid)
{
    *ppszSid = nullptr;
    HRESULT hr = E_UNEXPECTED;
    if (_pszUserSid != nullptr)
    {
        hr = SHStrDupW(_pszUserSid, ppszSid);
    }
    // Return S_FALSE with a null SID in ppszSid for the
    // credential to be associated with an empty user tile.

    return hr;
}

// GetFieldOptions to enable the password reveal button and touch keyboard auto-invoke in the password field.
HRESULT CSampleCredential::GetFieldOptions(DWORD dwFieldID,
                                           _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_FIELD_OPTIONS *pcpcfo)
{
    *pcpcfo = CPCFO_NONE;

    if (dwFieldID == SFI_PASSWORD)
    {
        *pcpcfo = CPCFO_ENABLE_PASSWORD_REVEAL;
    }
    else if (dwFieldID == SFI_TILEIMAGE)
    {
        *pcpcfo = CPCFO_ENABLE_TOUCH_KEYBOARD_AUTO_INVOKE;
    }

    return S_OK;
}
