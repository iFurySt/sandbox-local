package main

import (
	"errors"
	windows "golang.org/x/sys/windows"
)

// Exercise the same synchronous metadata handle Node/libuv uses. os.Stat can
// succeed via attribute queries without ever opening this directory.
func checkDirectoryMetadata(path string) error {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	h, err := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return err
	}
	var info windows.ByHandleFileInformation
	return errors.Join(windows.GetFileInformationByHandle(h, &info), windows.CloseHandle(h))
}
