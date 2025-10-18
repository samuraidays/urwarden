// cmd/fetch-blocklist/fetch_blocklist.go
//
// 使い方：
//
//	go run ./cmd/fetch-blocklist
//	# → data/blocklist.txt を自動生成（ドメインのみ／重複排除／ソート）
//
// 目的：
//
//	StevenBlack/hosts の "hosts" をダウンロードして、urwarden が扱いやすい
//	「ドメイン単体のリスト」に整形して保存する。
//
// ポイント：
//   - hosts形式の「IP アドレス ドメイン」行から、右端のドメインだけ抽出
//   - コメント行(#)や空行をスキップ
//   - 末尾のドットや大文字小文字のゆれを正規化
//   - 重複を排除してからアルファベット順で保存
//   - 保存先は data/blocklist.txt（無ければ作成）
package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// 取得元（必要に応じて切り替え可能）
var sources = []string{
	// StevenBlack/hosts の最新 hosts（生テキスト）
	"https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
	// もし高速にしたい場合は gzip 版などに切替も可能（例）
	// "https://someone.example/hosts.gz",
}

// 出力先
const outputPath = "data/blocklist.txt"

func main() {
	if err := run(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, "fetch-blocklist error:", err)
		os.Exit(1)
	}
	fmt.Println("OK: wrote", outputPath)
}

func run(ctx context.Context) error {
	// HTTPクライアント（タイムアウト・TLS設定付き）
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   15 * time.Second,
				KeepAlive: 15 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       30 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}

	// すべてのソースを順に取得して 1つの set に集約
	set := make(map[string]struct{}, 100_000)

	for _, src := range sources {
		if err := fetchAndParse(ctx, client, src, set); err != nil {
			return fmt.Errorf("fetch %s: %w", src, err)
		}
	}

	// set → ソート済みスライスへ
	domains := make([]string, 0, len(set))
	for d := range set {
		domains = append(domains, d)
	}
	sort.Strings(domains)

	// 出力ディレクトリ作成
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	// ヘッダコメント付きで保存
	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("create: %w", err)
	}
	defer func() {
		_ = f.Close()
	}()

	header := fmt.Sprintf(
		"# urwarden blocklist (domains only)\n# generated at: %s UTC\n# sources:\n",
		time.Now().UTC().Format(time.RFC3339),
	)
	if _, err := f.WriteString(header); err != nil {
		return err
	}
	for _, s := range sources {
		if _, err := f.WriteString("#   " + s + "\n"); err != nil {
			return err
		}
	}
	if _, err := f.WriteString("\n"); err != nil {
		return err
	}

	w := bufio.NewWriter(f)
	for _, d := range domains {
		if _, err := w.WriteString(d + "\n"); err != nil {
			return err
		}
	}
	if err := w.Flush(); err != nil {
		return err
	}
	return nil
}

// fetchAndParse は URL から hosts 形式（またはプレーンなドメイン列）を取得し、
// 見つけたドメインを set に追加する。
func fetchAndParse(ctx context.Context, client *http.Client, url string, set map[string]struct{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "urwarden-fetch-blocklist/0.1")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	var r io.Reader = resp.Body
	// もし Content-Encoding が gzip なら解凍（StevenBlackは通常プレーン）
	if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
		gr, gzErr := gzip.NewReader(resp.Body)
		if gzErr != nil {
			return gzErr
		}
		defer func() { _ = gr.Close() }()
		r = gr
	}

	sc := bufio.NewScanner(r)
	// 1行が長い場合に備えてバッファ拡張
	const maxLine = 1024 * 1024
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, maxLine)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue // コメント・空行をスキップ
		}

		// 例）"0.0.0.0 bad.example.com" / "127.0.0.1 foo.bar" / "malicious.test"
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		var dom string
		switch len(fields) {
		case 1:
			// ドメインだけが書かれている形式
			dom = fields[0]
		default:
			// hosts形式（"IP ドメイン" ...）の想定：右端をドメインとみなす
			dom = fields[len(fields)-1]
			// 先頭のフィールドがIPっぽいか軽くチェック（IP以外でも右端優先でOK）
			_ = net.ParseIP(fields[0]) // 使わないが念のための可読性
		}

		dom = normalizeDomain(dom)
		if dom == "" {
			continue
		}
		set[dom] = struct{}{}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return nil
}

// normalizeDomain はドメインの簡易正規化（小文字・末尾のドット除去・前後空白除去）。
func normalizeDomain(s string) string {
	if s = strings.TrimSpace(s); s == "" {
		return ""
	}
	// コメント断片が残っているケースへの防御（例: "bad.com # note"）
	if i := strings.IndexByte(s, '#'); i >= 0 {
		s = s[:i]
	}
	s = strings.ToLower(strings.Trim(s, "."))
	// 最低限のバリデーション（空やワイルドカードのみは除外）
	if s == "" || strings.ContainsAny(s, " /\\") {
		return ""
	}
	// ワイルドカードの "*.example.com" は v0.1 では採用しない（将来対応）
	if strings.HasPrefix(s, "*.") {
		return ""
	}
	// ドメインらしい見た目の緩いチェック（簡易）
	if !strings.Contains(s, ".") {
		// サブドメイン無しTLDなどを避けたい場合は除外
		return ""
	}
	return s
}
