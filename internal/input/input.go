package input

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// FromArgsOrInput は、(1) --input で指定されたファイル/STDIN からURLを読み込む
// か、(2) 位置引数(args) のURLを使います。
// - path == "" の場合は args をそのまま返す
// - path == "-" の場合は STDIN から読む
// - ファイルは1行1URL。空行・#コメント行はスキップ
func FromArgsOrInput(args []string, path string) ([]string, error) {
	if strings.TrimSpace(path) == "" {
		// 単発/複数の位置引数をそのまま利用
		// 例: urwarden https://a https://b
		return dedupe(args), nil
	}
	var r io.ReadCloser
	if path == "-" {
		// 標準入力
		r = os.Stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", path, err)
		}
		r = f
		defer func() { _ = r.Close() }()
	}
	sc := bufio.NewScanner(r)
	// 長い行でもある程度読めるようにバッファ拡張（必要に応じて調整）
	const maxLine = 1024 * 1024
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, maxLine)

	var out []string
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan: %w", err)
	}
	return dedupe(out), nil
}

func dedupe(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	var out []string
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
