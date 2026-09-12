package jshunter

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// jwtNames contains the pattern/rule names that indicate a JWT finding.
var jwtNames = map[string]struct{}{
	"Json Web Token":           {},
	"JSON Web Token":           {},
	"JWT Token":                {},
	"Kubernetes Token":         {},
	"Supabase Service Role Key": {},
	"Supabase Service Role JWT": {},
}

// isJWTPatternName returns true when the pattern name is known to match JWTs.
func isJWTPatternName(name string) bool {
	_, ok := jwtNames[name]
	return ok
}

// looksLikeJWTValue is a fast pre-check: a JWT must have three dot-separated
// segments where the first two start with "eyJ" (base64url for '{"').
func looksLikeJWTValue(v string) bool {
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return false
	}
	return strings.HasPrefix(parts[0], "eyJ") && strings.HasPrefix(parts[1], "eyJ")
}

// JWTInfo holds the decoded fields extracted from a JWT for display.
type JWTInfo struct {
	Algorithm   string
	Issuer      string
	Subject     string
	ExpiresAt   *time.Time
	ExtraClaims map[string]interface{} // role, scope, permissions, etc.
	Flags       []string               // CRITICAL / WEAK_KEY / NO_EXPIRY
}

// b64urlDecode decodes a base64url segment with or without padding.
func b64urlDecode(seg string) ([]byte, error) {
	// Add padding if missing.
	switch len(seg) % 4 {
	case 2:
		seg += "=="
	case 3:
		seg += "="
	}
	return base64.URLEncoding.DecodeString(seg)
}

// decodeJWT parses a JWT string and returns enrichment info, or nil if
// the token cannot be decoded as a valid JWT structure.
func decodeJWT(token string) *JWTInfo {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}

	headerBytes, err := b64urlDecode(parts[0])
	if err != nil {
		return nil
	}
	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil
	}

	payloadBytes, err := b64urlDecode(parts[1])
	if err != nil {
		return nil
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil
	}

	info := &JWTInfo{
		ExtraClaims: make(map[string]interface{}),
	}

	// Algorithm from header.
	if alg, ok := header["alg"].(string); ok {
		info.Algorithm = alg
	}

	// Standard claims from payload.
	if iss, ok := payload["iss"].(string); ok {
		info.Issuer = iss
	}
	if sub, ok := payload["sub"].(string); ok {
		info.Subject = sub
	}

	// Expiry: exp is a Unix timestamp (float64 in JSON).
	if expVal, ok := payload["exp"]; ok {
		var unixSec int64
		switch v := expVal.(type) {
		case float64:
			unixSec = int64(v)
		case json.Number:
			n, _ := v.Int64()
			unixSec = n
		}
		if unixSec > 0 {
			t := time.Unix(unixSec, 0).UTC()
			info.ExpiresAt = &t
		}
	}

	// Role / scope / permissions claims are interesting for priv-esc hunting.
	for _, key := range []string{"role", "scope", "permissions", "authorities", "groups", "email"} {
		if val, ok := payload[key]; ok {
			info.ExtraClaims[key] = val
		}
	}

	// --- Security flags ---

	alg := strings.ToLower(info.Algorithm)

	// alg=none: signature verification is disabled — trivially forgeable.
	if alg == "none" || alg == "" {
		info.Flags = append(info.Flags, "CRITICAL: alg=none — signature not verified")
	}

	// RS256 with a small RSA key (n < 256 bytes = < 2048 bits) in an embedded JWK.
	if strings.HasPrefix(alg, "rs") {
		if jwk, ok := header["jwk"].(map[string]interface{}); ok {
			if nStr, ok := jwk["n"].(string); ok {
				nBytes, err := b64urlDecode(nStr)
				if err == nil {
					// Parse as a big integer to get real bit length.
					n := new(big.Int).SetBytes(nBytes)
					bitLen := n.BitLen()
					if bitLen < 2048 {
						info.Flags = append(info.Flags,
							fmt.Sprintf("WEAK_KEY: embedded RSA key is %d bits (< 2048)", bitLen))
					}
				}
			}
		}
	}

	// No exp claim: token never expires.
	if info.ExpiresAt == nil {
		info.Flags = append(info.Flags, "NO_EXPIRY: token has no exp claim")
	}

	return info
}

// printJWTInfo prints the decoded JWT summary to stdout alongside the finding.
func printJWTInfo(info *JWTInfo, config *Config) {
	cyan := colors["CYAN"]
	yellow := colors["YELLOW"]
	red := colors["RED"]
	nc := colors["NC"]

	fmt.Printf("  %s[JWT]%s alg=%s", cyan, nc, info.Algorithm)
	if info.Issuer != "" {
		fmt.Printf("  iss=%s", info.Issuer)
	}
	if info.Subject != "" {
		fmt.Printf("  sub=%s", info.Subject)
	}

	now := time.Now().UTC()
	if info.ExpiresAt != nil {
		if now.After(*info.ExpiresAt) {
			fmt.Printf("  exp=EXPIRED (was %s)", info.ExpiresAt.Format("2006-01-02T15:04:05Z"))
		} else {
			remaining := info.ExpiresAt.Sub(now)
			fmt.Printf("  exp=%s (in %s)", info.ExpiresAt.Format("2006-01-02T15:04:05Z"), remaining.Round(time.Second))
		}
	}

	for k, v := range info.ExtraClaims {
		fmt.Printf("  %s=%v", k, v)
	}
	fmt.Println()

	for _, flag := range info.Flags {
		var color string
		if strings.HasPrefix(flag, "CRITICAL") {
			color = red
		} else {
			color = yellow
		}
		fmt.Printf("  %s[JWT-WARN]%s %s\n", color, nc, flag)
	}

	// Suppress the unused-variable warning when colors are disabled.
	_ = cyan
	_ = yellow
	_ = red
	_ = nc
}
