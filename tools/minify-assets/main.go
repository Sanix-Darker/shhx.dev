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

	sourceDir := filepath.Join(root, "internal", "app", "assets")
	outputDir := filepath.Join(root, "internal", "app", "static")

	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		fail(err)
	}

	if err := writeMinified(filepath.Join(sourceDir, "app.js"), filepath.Join(outputDir, "app.js"), minifyJS); err != nil {
		fail(err)
	}
	if err := writeMinified(filepath.Join(sourceDir, "styles.css"), filepath.Join(outputDir, "styles.css"), minifyCSS); err != nil {
		fail(err)
	}
}

func writeMinified(srcPath, dstPath string, minifier func([]byte) []byte) error {
	src, err := os.ReadFile(srcPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", srcPath, err)
	}
	minified := minifier(src)
	return os.WriteFile(dstPath, minified, 0o644)
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
