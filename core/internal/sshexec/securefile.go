package sshexec

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// openSingleLinkRegular opens only a direct, regular, single-link child of an
// already-existing real directory. Holding the parent directory descriptor and
// using openat closes the basename swap race; O_NOFOLLOW rejects a final
// symlink, O_NONBLOCK prevents a FIFO/device from hanging the helper, and the
// link-count check rejects hardlinks to another user-owned file before any
// chmod, append, truncate, or flock occurs.
func openSingleLinkRegular(path string, flags int, perm os.FileMode) (*os.File, error) {
	clean := filepath.Clean(path)
	base := filepath.Base(clean)
	if base == "." || base == ".." || base == string(filepath.Separator) {
		return nil, fmt.Errorf("sshexec: invalid file path %q", path)
	}
	parent := filepath.Dir(clean)
	dirFD, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("sshexec: open parent directory %q: %w", parent, err)
	}
	openFlags := flags | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
	fd := -1
	var openErr error
	for attempt := 0; attempt < 4; attempt++ {
		fd, openErr = unix.Openat(dirFD, base, openFlags, uint32(perm.Perm()))
		// Darwin can transiently report ENOENT when several processes race to
		// create the same openat child. Retry against the already-anchored
		// parent; every attempt retains the same validation guarantees.
		if flags&unix.O_CREAT == 0 || (!errors.Is(openErr, unix.ENOENT) && !errors.Is(openErr, unix.EINTR)) {
			break
		}
	}
	closeDirErr := unix.Close(dirFD)
	if openErr != nil {
		return nil, errors.Join(fmt.Errorf("sshexec: open %q: %w", clean, openErr), closeDirErr)
	}
	if closeDirErr != nil {
		return nil, errors.Join(fmt.Errorf("sshexec: close parent directory %q: %w", parent, closeDirErr), unix.Close(fd))
	}

	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, errors.Join(fmt.Errorf("sshexec: inspect %q: %w", clean, err), unix.Close(fd))
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, errors.Join(fmt.Errorf("sshexec: %q is not a regular file", clean), unix.Close(fd))
	}
	if stat.Nlink != 1 {
		return nil, errors.Join(fmt.Errorf("sshexec: %q has %d links; refusing hardlink", clean, stat.Nlink), unix.Close(fd))
	}
	f := os.NewFile(uintptr(fd), clean)
	if f == nil {
		return nil, errors.Join(fmt.Errorf("sshexec: wrap file %q", clean), unix.Close(fd))
	}
	return f, nil
}
