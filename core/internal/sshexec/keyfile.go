package sshexec

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

const maxPrivateKeyFileBytes = 1 << 20

// readKeyFile loads a private-key file. It is a thin wrapper so the caller can
// zeroize the returned bytes uniformly with the vault path.
func readKeyFile(path string) ([]byte, error) {
	f, err := openSingleLinkRegular(path, unix.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var before unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &before); err != nil {
		return nil, fmt.Errorf("sshexec: inspect private key: %w", err)
	}
	if before.Uid != uint32(os.Geteuid()) || before.Mode&0o077 != 0 {
		return nil, fmt.Errorf("sshexec: private key must be current-user-owned and not group/world accessible")
	}
	if before.Size < 0 || before.Size > maxPrivateKeyFileBytes {
		return nil, fmt.Errorf("sshexec: private key exceeds %d-byte limit", maxPrivateKeyFileBytes)
	}

	raw, err := io.ReadAll(io.LimitReader(f, maxPrivateKeyFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("sshexec: read private key: %w", err)
	}
	if len(raw) > maxPrivateKeyFileBytes {
		zero(raw)
		return nil, fmt.Errorf("sshexec: private key exceeds %d-byte limit", maxPrivateKeyFileBytes)
	}

	var after unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &after); err != nil {
		zero(raw)
		return nil, fmt.Errorf("sshexec: re-inspect private key: %w", err)
	}
	if before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size ||
		before.Mode != after.Mode || before.Nlink != after.Nlink || before.Uid != after.Uid ||
		int64(len(raw)) != after.Size {
		zero(raw)
		return nil, fmt.Errorf("sshexec: private key changed while it was read")
	}
	return raw, nil
}
