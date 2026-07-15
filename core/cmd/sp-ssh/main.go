// Command sp-ssh runs one SSH operation for the Mac app.
//
// For exec, the app provides an inherited socket used only for signing. The
// private key stays in the app. Key import uses stdin because the key has not
// entered the vault yet. The helper holds no vault or policy state.
package main

import (
	"fmt"
	"os"

	"github.com/sallyport/sallyport/internal/sshexec"
)

func main() {
	if err := sshexec.RunHelper(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "sp-ssh:", err)
		os.Exit(1)
	}
}
