# jsleak

![jsleak: JavaScript artifact inspection](assets/project-mark.svg)

Extracts candidate secrets and endpoints from JavaScript. This fork adds source-map handling, input from extracted APK directories and JWT claim decoding.

Maintained by [unrandoms](https://github.com/unrandoms), derived from [cc1a2b/JShunter](https://github.com/cc1a2b/JShunter).

## Fork-specific work

- [`internal/jshunter/apk.go`](internal/jshunter/apk.go)
- [`internal/jshunter/sourcemap.go`](internal/jshunter/sourcemap.go)
- [`internal/jshunter/jwt_decode.go`](internal/jshunter/jwt_decode.go)

## Validation and limits

APK input means an already extracted directory, not a complete APK decompiler. Decoded JWT claims are unverified data.

This documentation update does not certify all inherited features. The [archived reference](UPSTREAM_README.md) describes the original ecosystem; its package names and release links may target upstream rather than this fork.

## Credits

See [CREDITS.md](CREDITS.md) for the distinction between the original implementation and this fork's adaptations. Original licenses and copyright notices remain in the repository.
