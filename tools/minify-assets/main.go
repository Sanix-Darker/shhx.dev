package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	root, err := os.Getwd()
	if err != nil {
		fail(err)
	}

	outputDir := filepath.Join(root, "internal", "app", "static")

	if err := os.MkdirAll(outputDir, 0o750); err != nil {
		fail(err)
	}
	if err := os.MkdirAll(filepath.Join(outputDir, "vendor"), 0o750); err != nil {
		fail(err)
	}

	if err := writeMinified(root, filepath.Join("internal", "app", "assets", "app.js"), filepath.Join("internal", "app", "static", "app.js"), minifyJS); err != nil {
		fail(err)
	}
	if err := writeMinified(root, filepath.Join("internal", "app", "assets", "styles.css"), filepath.Join("internal", "app", "static", "styles.css"), minifyCSS); err != nil {
		fail(err)
	}
	if err := writeCopied(root, filepath.Join("internal", "app", "assets", "vendor", "openpgp.min.js"), filepath.Join("internal", "app", "static", "vendor", "openpgp.min.js")); err != nil {
		fail(err)
	}
}

func writeMinified(rootPath, srcPath, dstPath string, minifier func([]byte) []byte) error {
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return fmt.Errorf("open root %s: %w", rootPath, err)
	}
	defer root.Close()

	src, err := root.ReadFile(srcPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", srcPath, err)
	}
	minified := minifier(src)
	return root.WriteFile(dstPath, minified, 0o640)
}

func writeCopied(rootPath, srcPath, dstPath string) error {
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return fmt.Errorf("open root %s: %w", rootPath, err)
	}
	defer root.Close()

	src, err := root.ReadFile(srcPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", srcPath, err)
	}
	return root.WriteFile(dstPath, src, 0o640)
}

func minifyJS(src []byte) []byte {
	var out bytes.Buffer
	scanner := bufio.NewScanner(bytes.NewReader(src))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		out.WriteString(line)
		out.WriteByte('\n')
	}
	if err := scanner.Err(); err != nil && err != io.EOF {
		fail(err)
	}
	return out.Bytes()
}

func minifyCSS(src []byte) []byte {
	text := strings.ReplaceAll(string(src), "\n", " ")
	text = strings.ReplaceAll(text, "\t", " ")
	text = collapseSpaces(text)

	replacements := []string{
		": ", ":",
		"; ", ";",
		"{ ", "{",
		" }", "}",
		", ", ",",
		"> ", ">",
		" <", "<",
		"( ", "(",
		" )", ")",
	}
	for i := 0; i < len(replacements); i += 2 {
		text = strings.ReplaceAll(text, replacements[i], replacements[i+1])
	}

	return []byte(strings.TrimSpace(text))
}

func collapseSpaces(input string) string {
	fields := strings.Fields(input)
	return strings.Join(fields, " ")
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
