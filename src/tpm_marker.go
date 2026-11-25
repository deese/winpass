package main

import "errors"

// The marker records that TPM mode was set up. It lets activeMode decide with
// one cheap Credential Manager read instead of opening the TPM provider, which
// would add about half a second to every write for users who never use the
// TPM. The target is outside the "winpass/" prefix, so it never appears in
// listings, and it is named after the key so tests can use throwaway keys.
const tpmMarkerPrefix = "winpass-config/tpm/"

func tpmMarkerTarget() string {
	return tpmMarkerPrefix + tpmKeyName
}

func hasTPMMarker() (bool, error) {
	_, err := credReadTarget(tpmMarkerTarget())
	if err == nil {
		return true, nil
	}
	if errors.Is(err, errEntryNotFound) {
		return false, nil
	}
	return false, err
}

func setTPMMarker() error {
	return credWriteTarget(tpmMarkerTarget(), []byte("1"))
}

func clearTPMMarker() error {
	err := credDeleteTarget(tpmMarkerTarget())
	if err == nil || errors.Is(err, errEntryNotFound) {
		return nil
	}
	return err
}
