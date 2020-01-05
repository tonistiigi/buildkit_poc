package snapshot

import (
	"github.com/containerd/containerd/mount"
)

func (lm *localMounter) Unmount() error {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	if lm.target != "" {
		if err := mount.Unmount(lm.target, 0); err != nil {
			return err
		}
		lm.target = ""
	}

	if lm.release != nil {
		return lm.release()
	}

	return nil
}
