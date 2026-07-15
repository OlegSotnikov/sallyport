// Package dlp masks injected values and a fixed set of credential patterns.
// It is not a general DLP engine.
package dlp

import (
	"bytes"
	"regexp"
)

var patternExpressions = []string{
	`(?i)bearer\s+[A-Za-z0-9._\-]{8,}`,
	`gh[pousr]_[A-Za-z0-9]{20,}`,                  // GitHub
	`glpat-[A-Za-z0-9_\-]{16,}`,                   // GitLab PAT
	`AKIA[0-9A-Z]{16}`,                            // AWS access key id
	`(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}`, // Stripe
	`sk-(?:ant-)?[A-Za-z0-9_\-]{20,}`,             // OpenAI / Anthropic
	`xox[baprse]-[A-Za-z0-9\-]{10,}`,              // Slack
	`AIza[0-9A-Za-z_\-]{35}`,                      // Google API key
	`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`,
	`eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}`, // JWT
}

var patterns, patternsValid = compilePatterns(patternExpressions)

// Static DLP configuration is a security boundary too. MustCompile would turn
// one malformed future pattern into an init-time process crash. Keep the error
// as state; RedactWith then masks the complete non-empty response fail closed.
func compilePatterns(expressions []string) ([]*regexp.Regexp, bool) {
	compiled := make([]*regexp.Regexp, 0, len(expressions))
	for _, expression := range expressions {
		re, err := regexp.Compile(expression)
		if err != nil {
			return nil, false
		}
		compiled = append(compiled, re)
	}
	return compiled, true
}

const (
	// maskGeneric masks a value matched by one of the known secret shapes.
	maskGeneric = "«redacted»"
	// maskCredential marks an exact injected-value match.
	maskCredential = "«redacted:sallyport-credential»"
)

// Redact masks known secret shapes and returns the redaction count.
func Redact(b []byte) ([]byte, int) {
	return RedactWith(b, nil)
}

// RedactWith masks literal injected values and known credential patterns. The
// caller owns secrets and should clear them after this call.
func RedactWith(b []byte, secrets [][]byte) ([]byte, int) {
	count := 0
	// Replacement functions return new slices and do not modify b.
	out := b
	if !patternsValid {
		if len(out) == 0 {
			return []byte{}, 0
		}
		return []byte(maskGeneric), 1
	}
	// Mask exact values before the generic pattern pass.
	for _, s := range secrets {
		if len(s) == 0 {
			continue
		}
		if n := bytes.Count(out, s); n > 0 {
			count += n
			out = bytes.ReplaceAll(out, s, []byte(maskCredential))
			// Remove matches formed across a replacement boundary.
			for bytes.Contains(out, s) {
				n = bytes.Count(out, s)
				count += n
				out = bytes.ReplaceAll(out, s, nil)
			}
		}
	}
	for _, re := range patterns {
		out = re.ReplaceAllFunc(out, func(m []byte) []byte {
			count++
			return []byte(maskGeneric)
		})
	}
	// Repeat exact-value removal because one replacement can form another match.
	for {
		changed := false
		for _, s := range secrets {
			if len(s) == 0 {
				continue
			}
			if n := bytes.Count(out, s); n > 0 {
				count += n
				out = bytes.ReplaceAll(out, s, nil)
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	return out, count
}
