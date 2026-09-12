package jshunter

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// processApkDir walks an APK extraction directory produced by jadx or apktool
// and scans every *.js file and the React Native bundle
// (assets/index.android.bundle) for secrets using the full pattern engine.
//
// Findings are tagged with source = "apk:<relative_path>" so operators can
// locate the exact file inside the extracted archive. Binary files (not valid
// UTF-8) are skipped gracefully rather than producing noise or crashing.
func processApkDir(dir string, config *Config) {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		fmt.Printf("[%sERROR%s] --apk-dir: cannot resolve %q: %v\n",
			colors["RED"], colors["NC"], dir, err)
		return
	}

	if _, err := os.Stat(absDir); os.IsNotExist(err) {
		fmt.Printf("[%sERROR%s] --apk-dir: directory not found: %s\n",
			colors["RED"], colors["NC"], absDir)
		return
	}

	scanned := 0
	walkErr := filepath.WalkDir(absDir, func(path string, d fs.DirEntry, walkErrIn error) error {
		if walkErrIn != nil {
			// Skip unreadable entries silently; surface only in verbose mode.
			if config.Verbose {
				fmt.Printf("[%sWARN%s] apk: walk error at %s: %v\n",
					colors["YELLOW"], colors["NC"], path, walkErrIn)
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}

		rel, _ := filepath.Rel(absDir, path)
		name := d.Name()

		// Accept *.js files and the React Native production bundle.
		isJSFile := strings.HasSuffix(name, ".js")
		isRNBundle := rel == filepath.Join("assets", "index.android.bundle") ||
			// Also catch forward-slash path separator on Windows builds.
			rel == "assets/index.android.bundle"

		if !isJSFile && !isRNBundle {
			return nil
		}

		data, readErr := os.ReadFile(path)
		if readErr != nil {
			if config.Verbose {
				fmt.Printf("[%sWARN%s] apk: cannot read %s: %v\n",
					colors["YELLOW"], colors["NC"], rel, readErr)
			}
			return nil
		}

		// Skip binary files: not valid UTF-8 would produce garbage matches.
		if !utf8.Valid(data) {
			if config.Verbose {
				fmt.Printf("[%sWARN%s] apk: skipping binary file %s\n",
					colors["YELLOW"], colors["NC"], rel)
			}
			return nil
		}

		src := "apk:" + rel
		if globalStats != nil {
			statAdd(&globalStats.BytesParsed, int64(len(data)))
		}
		processed := processJSAnalysis(data, config)
		reportMatchesWithConfig(src, processed, config)
		scanned++
		return nil
	})

	if walkErr != nil && config.Verbose {
		fmt.Printf("[%sWARN%s] apk: walk terminated early: %v\n",
			colors["YELLOW"], colors["NC"], walkErr)
	}
	if !config.Quiet {
		fmt.Fprintf(os.Stderr, "[%sINFO%s] apk: scanned %d JS/bundle files in %s\n",
			colors["CYAN"], colors["NC"], scanned, absDir)
	}
}
