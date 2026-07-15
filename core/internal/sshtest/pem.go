package sshtest

import (
	"encoding/pem"
)

// encodePEM serializes a *pem.Block to bytes.
func encodePEM(block *pem.Block) []byte { return pem.EncodeToMemory(block) }
