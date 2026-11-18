// Copyright © 2018 Nik Unger
//
// This file is part of The PBC Go Wrapper.
//
// The PBC Go Wrapper is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// The PBC Go Wrapper is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
// License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with The PBC Go Wrapper. If not, see <http://www.gnu.org/licenses/>.
//
// The PBC Go Wrapper makes use of The PBC library. The PBC Library and its use
// are covered under the terms of the GNU Lesser General Public License
// version 3, or (at your option) any later version.

// +build !linux,!darwin,!freebsd

package pbc

/*
#include <stdlib.h>
#include "memstream.h"
#ifdef _WIN32
#include <windows.h>
#include <stdint.h>
#include <io.h>
#include <fcntl.h>
#endif

struct memstream_s {
	FILE* fd;
};

memstream_t* pbc_open_memstream() {
#ifdef _WIN32
	// MSVCRT tmpfile() may try the drive root and fail for ordinary users.
	// Use the user's temporary directory and delete the file on handle close.
	wchar_t directory[MAX_PATH], filename[MAX_PATH];
	DWORD length = GetTempPathW(MAX_PATH, directory);
	if (length == 0 || length >= MAX_PATH) return NULL;
	if (!GetTempFileNameW(directory, L"pbc", 0, filename)) return NULL;
	HANDLE handle = CreateFileW(filename, GENERIC_READ | GENERIC_WRITE,
		0, NULL, OPEN_EXISTING,
		FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL);
	if (handle == INVALID_HANDLE_VALUE) {
		DeleteFileW(filename);
		return NULL;
	}
	int descriptor = _open_osfhandle((intptr_t)handle, _O_RDWR | _O_BINARY);
	if (descriptor == -1) {
		CloseHandle(handle);
		return NULL;
	}
	FILE* fd = _fdopen(descriptor, "w+b");
	if (fd == NULL) {
		_close(descriptor);
		return NULL;
	}
#else
	FILE* fd = tmpfile();
	if (fd == NULL) return NULL;
#endif
	memstream_t* result = malloc(sizeof(memstream_t));
	if (result == NULL) {
		fclose(fd);
		return NULL;
	}
	result->fd = fd;
	return result;
}

FILE* pbc_memstream_to_fd(memstream_t* m) { return m->fd; }

int pbc_close_memstream(memstream_t* m, char** bufp, size_t* sizep) {
	*bufp = NULL;
	*sizep = 0;

	FILE* fd = m->fd;
	m->fd = NULL;
	free(m);
	m = NULL;

	if (!ferror(fd)) {
		// CHARE local portability fix: terminate the allocated byte buffer,
		// not the caller's pointer array. Check I/O before allocating/reading.
		if (fseek(fd, 0, SEEK_END) == 0) {
			long length = ftell(fd);
			if (length >= 0 && fseek(fd, 0, SEEK_SET) == 0) {
				*sizep = (size_t)length;
				*bufp = malloc(*sizep + 1);
				if (*bufp != NULL) {
					size_t readBytes = fread(*bufp, 1, *sizep, fd);
					if (readBytes == *sizep && !ferror(fd)) {
						(*bufp)[*sizep] = '\0';
					} else {
						free(*bufp);
						*bufp = NULL;
					}
				}
			}
		}
	}
	if (*bufp == NULL) *sizep = 0;
	fclose(fd);
	return (*bufp != NULL);
}
*/
import "C"
