//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.
//
// CSampleProvider implements ICredentialProvider, which is the main
// interface that logonUI uses to decide which tiles to display.
// In this sample, we will display one tile that uses each of the nine
// available UI controls.

#include <initguid.h>
#include "CSampleProvider.h"
#include "CSampleCredential.h"
#include "guid.h"

extern wchar_t	DebugLogBuff[512];

CSampleProvider::CSampleProvider():
    _cRef(1),
    _pCredential(nullptr),
    _pCredProviderUserArray(nullptr)
{
	OutLog(L"CSampleProvider::CSampleProvider() - in");

    DllAddRef();

	OutLog(L"CSampleProvider::CSampleProvider() - out");
}

CSampleProvider::~CSampleProvider()
{
	OutLog(L"CSampleProvider::~CSampleProvider() - in");

    if (_pCredential != nullptr)
    {
        _pCredential->Release();
        _pCredential = nullptr;
    }
    if (_pCredProviderUserArray != nullptr)
    {
        _pCredProviderUserArray->Release();
        _pCredProviderUserArray = nullptr;
    }

    DllRelease();

	OutLog(L"CSampleProvider::~CSampleProvider() - out");
}

// SetUsageScenario is the provider's cue that it's going to be asked for tiles
// in a subsequent call.
// ��SetUsageScenario�́A�㑱�̌Ăяo���Ń^�C����v�������Ƃ����v���o�C�_�[�̃L���[�ł��B
HRESULT CSampleProvider::SetUsageScenario(
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    DWORD /*dwFlags*/)
{
	OutLog(L"CSampleProvider::SetUsageScenario - in");

    HRESULT hr;

    // Decide which scenarios to support here. Returning E_NOTIMPL simply tells the caller
    // that we're not designed for that scenario.
	// �������ŃT�|�[�g����V�i���I�����肵�܂��B
	// E_NOTIMPL��Ԃ����Ƃ́A���̃V�i���I�p�ɐ݌v����Ă��Ȃ����Ƃ��Ăяo�����ɓ`���邾���ł��B
    switch (cpus)
    {
    case CPUS_LOGON:
    case CPUS_UNLOCK_WORKSTATION:
		OutLog(L" - CPUS_LOGON/CPUS_UNLOCK_WORKSTATION");
		// The reason why we need _fRecreateEnumeratedCredentials is because ICredentialProviderSetUserArray::SetUserArray() is called after ICredentialProvider::SetUsageScenario(),
        // while we need the ICredentialProviderUserArray during enumeration in ICredentialProvider::GetCredentialCount()���̂��ƌĂяo�����
		// ��ICredentialProviderSetUserArray::SetUserArray()�̂��߂�
		//   _fRecreateEnumeratedCredentials��TRUE�ɂ��܂��B
		//   ICredentialProvider::GetCredentialCount()�̗񋓒���ICredentialProviderUserArray���K�v�Ȋ�
        _cpus = cpus;
        _fRecreateEnumeratedCredentials = true;
        hr = S_OK;
        break;

    case CPUS_CHANGE_PASSWORD:
    case CPUS_CREDUI:
		OutLog(L" - CPUS_CHANGE_PASSWORD/CPUS_CREDUI");
		hr = E_NOTIMPL;
        break;

    default:
        hr = E_INVALIDARG;
        break;
    }

	OutLog(L"CSampleProvider::SetUsageScenario - out");
	return hr;
}

// SetSerialization takes the kind of buffer that you would normally return to LogonUI for
// an authentication attempt.  It's the opposite of ICredentialProviderCredential::GetSerialization.
// GetSerialization is implement by a credential and serializes that credential.  Instead,
// SetSerialization takes the serialization and uses it to create a tile.
//
// SetSerialization is called for two main scenarios.  The first scenario is in the credui case
// where it is prepopulating a tile with credentials that the user chose to store in the OS.
// The second situation is in a remote logon case where the remote client may wish to
// prepopulate a tile with a username, or in some cases, completely populate the tile and
// use it to logon without showing any UI.
//
// If you wish to see an example of SetSerialization, please see either the SampleCredentialProvider
// sample or the SampleCredUICredentialProvider sample.  [The logonUI team says, "The original sample that
// this was built on top of didn't have SetSerialization.  And when we decided SetSerialization was
// important enough to have in the sample, it ended up being a non-trivial amount of work to integrate
// it into the main sample.  We felt it was more important to get these samples out to you quickly than to
// hold them in order to do the work to integrate the SetSerialization changes from SampleCredentialProvider
// into this sample.]
HRESULT CSampleProvider::SetSerialization(
    _In_ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION const * /*pcpcs*/)
{
    return E_NOTIMPL;
}

// Called by LogonUI to give you a callback.  Providers often use the callback if they
// some event would cause them to need to change the set of tiles that they enumerated.
// ��LogonUI�ɂ���ČĂяo����A�R�[���o�b�N��񋟂��܂��B
//   �v���o�C�_�[�́A�C�x���g�ɂ���ė񋓂����^�C���̃Z�b�g��ύX����K�v������ꍇ�ɁA
//   �R�[���o�b�N���g�p���邱�Ƃ��悭����܂�
HRESULT CSampleProvider::Advise(
    _In_ ICredentialProviderEvents * /*pcpe*/,
    _In_ UINT_PTR /*upAdviseContext*/)
{
    return E_NOTIMPL;
}

// Called by LogonUI when the ICredentialProviderEvents callback is no longer valid.
// ��ICredentialProviderEvents�R�[���o�b�N�������ɂȂ����Ƃ���LogonUI�ɂ���ČĂяo����܂��B
HRESULT CSampleProvider::UnAdvise()
{
    return E_NOTIMPL;
}

// Called by LogonUI to determine the number of fields in your tiles.  This
// does mean that all your tiles must have the same number of fields.
// This number must include both visible and invisible fields. If you want a tile
// to have different fields from the other tiles you enumerate for a given usage
// scenario you must include them all in this count and then hide/show them as desired
// using the field descriptors.
// ��LogonUI�ɂ���ČĂяo����A�^�C�����̃t�B�[���h�̐������肵�܂��B
//   ����́A���ׂẴ^�C���ɓ������̃t�B�[���h���K�v�ł��邱�Ƃ��Ӗ����܂��B
//   ���̔ԍ��ɂ́A�\���t�B�[���h�Ɣ�\���t�B�[���h�̗������܂߂�K�v������܂��B
//   ����̎g�p�V�i���I�ŗ񋓂��鑼�̃^�C���Ƃ͈قȂ�t�B�[���h���^�C���Ɏ����������ꍇ�́A
//   ���������ׂĂ��̃J�E���g�Ɋ܂߂Ă���A
//   �t�B�[���h�L�q�q���g�p���ĕK�v�ɉ����Ĕ�\�� / �\������K�v������܂��B
HRESULT CSampleProvider::GetFieldDescriptorCount(
    _Out_ DWORD *pdwCount)
{
	// 13��Ԃ�
    *pdwCount = SFI_NUM_FIELDS;
    return S_OK;
}

// Gets the field descriptor for a particular field.
// ������̃t�B�[���h�̃t�B�[���h�L�q�q���擾���܂��B
HRESULT CSampleProvider::GetFieldDescriptorAt(
    DWORD dwIndex,
    _Outptr_result_nullonfailure_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR **ppcpfd)
{
    HRESULT hr;
    *ppcpfd = nullptr;

    // Verify dwIndex is a valid field.
    if ((dwIndex < SFI_NUM_FIELDS) && ppcpfd)
    {
        hr = FieldDescriptorCoAllocCopy(s_rgCredProvFieldDescriptors[dwIndex], ppcpfd);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Sets pdwCount to the number of tiles that we wish to show at this time.
// Sets pdwDefault to the index of the tile which should be used as the default.
// The default tile is the tile which will be shown in the zoomed view by default. If
// more than one provider specifies a default the last used cred prov gets to pick
// the default. If *pbAutoLogonWithDefault is TRUE, LogonUI will immediately call
// GetSerialization on the credential you've specified as the default and will submit
// that credential for authentication without showing any further UI.
// ��pdwCount���A���̎��_�ŕ\������^�C���̐��ɐݒ肵�܂��B
//   pdwDefault���A�f�t�H���g�Ƃ��Ďg�p�����^�C���̃C���f�b�N�X�ɐݒ肵�܂��B
//   �f�t�H���g�̃^�C���́A�Y�[�����ꂽ�r���[�Ƀf�t�H���g�ŕ\�������^�C���ł��B
//   �����̃v���o�C�_�[���f�t�H���g���w�肷��ꍇ�A�Ō�Ɏg�p���ꂽcred prov���f�t�H���g��I�����܂��B
//   *pbAutoLogonWithDefault��TRUE�̏ꍇ�A
//   LogonUI�́A�f�t�H���g�Ƃ��Ďw�肵�����i����GetSerialization�������ɌĂяo���A
//   ����ȏ��UI��\�������ɔF�؂̂��߂ɂ��̎��i���𑗐M���܂��B(�������O�C��)
HRESULT CSampleProvider::GetCredentialCount(
    _Out_ DWORD *pdwCount,
    _Out_ DWORD *pdwDefault,
    _Out_ BOOL *pbAutoLogonWithDefault)
{
	// �f�t�H���g�^�C���̃C���f�b�N�X(-1)
    *pdwDefault = CREDENTIAL_PROVIDER_NO_DEFAULT;
	// �������O�C��
    *pbAutoLogonWithDefault = FALSE;

	// 
    if (_fRecreateEnumeratedCredentials)
    {
        _fRecreateEnumeratedCredentials = false;
        _ReleaseEnumeratedCredentials();
        _CreateEnumeratedCredentials();
    }

    *pdwCount = 1;

    return S_OK;
}

// Returns the credential at the index specified by dwIndex. This function is called by logonUI to enumerate
// the tiles.
HRESULT CSampleProvider::GetCredentialAt(
    DWORD dwIndex,
    _Outptr_result_nullonfailure_ ICredentialProviderCredential **ppcpc)
{
    HRESULT hr = E_INVALIDARG;
    *ppcpc = nullptr;

    if ((dwIndex == 0) && ppcpc)
    {
        hr = _pCredential->QueryInterface(IID_PPV_ARGS(ppcpc));
    }
    return hr;
}

// This function will be called by LogonUI after SetUsageScenario succeeds.
// Sets the User Array with the list of users to be enumerated on the logon screen.
HRESULT CSampleProvider::SetUserArray(_In_ ICredentialProviderUserArray *users)
{
    if (_pCredProviderUserArray)
    {
        _pCredProviderUserArray->Release();
    }
    _pCredProviderUserArray = users;
    _pCredProviderUserArray->AddRef();
    return S_OK;
}

void CSampleProvider::_CreateEnumeratedCredentials()
{
    switch (_cpus)
    {
    case CPUS_LOGON:
    case CPUS_UNLOCK_WORKSTATION:
        {
            _EnumerateCredentials();
            break;
        }
    default:
        break;
    }
}

void CSampleProvider::_ReleaseEnumeratedCredentials()
{
    if (_pCredential != nullptr)
    {
        _pCredential->Release();
        _pCredential = nullptr;
    }
}

HRESULT CSampleProvider::_EnumerateCredentials()
{
	OutLog(L"CSampleProvider::_EnumerateCredentials - in");

    HRESULT hr = E_UNEXPECTED;
    if (_pCredProviderUserArray != nullptr)
    {
        DWORD dwUserCount;
        _pCredProviderUserArray->GetCount(&dwUserCount);

		swprintf_s(DebugLogBuff,512, L"- dwUserCount=%d", dwUserCount);
		OutLog(DebugLogBuff);

		if (dwUserCount > 0) {
            ICredentialProviderUser *pCredUser;
            hr = _pCredProviderUserArray->GetAt(0, &pCredUser);
			//hr = _pCredProviderUserArray->GetAt(1, &pCredUser);
			if (SUCCEEDED(hr)) {
                _pCredential = new(std::nothrow) CSampleCredential();
				if (_pCredential != nullptr) {
                    hr = _pCredential->Initialize(_cpus, s_rgCredProvFieldDescriptors, s_rgFieldStatePairs, pCredUser);
					if (FAILED(hr)) {
                        _pCredential->Release();
                        _pCredential = nullptr;
                    }
				}else {
                    hr = E_OUTOFMEMORY;
                }
                pCredUser->Release();
            }
        }
    }
	OutLog(L"CSampleProvider::_EnumerateCredentials - out");

    return hr;
}

// Boilerplate code to create our provider.
HRESULT CSample_CreateInstance(_In_ REFIID riid, _Outptr_ void **ppv)
{
    HRESULT hr;
    CSampleProvider *pProvider = new(std::nothrow) CSampleProvider();
    if (pProvider)
    {
        hr = pProvider->QueryInterface(riid, ppv);
        pProvider->Release();
    }
    else
    {
        hr = E_OUTOFMEMORY;
    }
    return hr;
}
