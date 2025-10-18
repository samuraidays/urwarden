package main

import (
	"bufio" // [NEW]
	"flag"
	"fmt"
	"io" // [NEW]
	"os"
	"strings" // [NEW]

	// 内部パッケージをインポート
	"github.com/samuraidays/urwarden/internal/output" // JSON出力
	"github.com/samuraidays/urwarden/internal/parse"  // URLの分解・正規化
	"github.com/samuraidays/urwarden/internal/rules"  // 判定ルール（blocklistやTLDなど）
	"github.com/samuraidays/urwarden/internal/score"  // スコア集計とラベル付け
	"github.com/samuraidays/urwarden/internal/version"
)

const (
	exitOK       = 0 // 正常終了
	exitInternal = 1 // 内部エラー（ファイルI/Oや想定外の例外）
	exitInput    = 2 // 入力エラー（URL不正など）
)

func main() {
	// ---------------------------------
	// [NEW] フラグ: --input を追加
	// ---------------------------------
	var (
		showVersion bool
		infile      string
	)
	flag.BoolVar(&showVersion, "version", false, "show version and exit")
	flag.StringVar(&infile, "input", "", "path to file with URLs (one per line). Use '-' for stdin") // [NEW]

	// [NEW] Usageのカスタム
	flag.CommandLine.SetOutput(os.Stderr)
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage:")
		fmt.Fprintln(os.Stderr, "  urwarden <URL> [<URL> ...] [--input file|-] [--version]")
		fmt.Fprintln(os.Stderr, "Examples:")
		fmt.Fprintln(os.Stderr, "  urwarden 'https://bad.example.com/login'")
		fmt.Fprintln(os.Stderr, "  urwarden --input urls.txt")
		fmt.Fprintln(os.Stderr, "  cat urls.txt | urwarden --input -")
		fmt.Fprintln(os.Stderr, "Exit codes: 0=ok, 1=internal error, 2=input error")
	}

	flag.Parse()

	if showVersion {
		fmt.Printf("urwarden %s (commit %s, date %s, build %s)\n",
			version.Version, version.Commit, version.BuildDate, version.BuildNumber)
		os.Exit(exitOK)
	}

	// ---------------------------------
	// [NEW] URLの収集（位置引数 or --input）
	// ---------------------------------
	urls, err := collectURLs(flag.Args(), infile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(exitInput)
	}
	if len(urls) == 0 {
		flag.Usage()
		os.Exit(exitInput)
	}

	// ---------------------------------
	// [CHANGED] 複数URLをループ処理（1URL→1行JSON）
	// ---------------------------------
	hadInputError := false
	for _, inputURL := range urls {
		// 1) URLをパースして正規化
		norm, perr := parse.NormalizeURL(inputURL)
		if perr != nil {
			// このURLはスキップしつつ、最後に exit=2 で終了
			fmt.Fprintln(os.Stderr, perr.Error())
			hadInputError = true
			continue
		}

		// 2) 3つのルールを評価（blocklistは従来どおり固定パス）
		reasons := rules.EvaluateAll(norm, "data/blocklist.txt")

		// 3) スコア集計とラベル判定
		total, label := score.Aggregate(reasons)

		// 4) JSON形式で結果を出力（JSON Lines）
		if err := output.WriteResultJSON(inputURL, norm, total, label, reasons); err != nil {
			fmt.Fprintln(os.Stderr, "failed to write json:", err.Error())
			os.Exit(exitInternal)
		}
	}

	// 5) 終了コード（入力エラーが1件でもあれば 2、なければ 0）
	if hadInputError {
		os.Exit(exitInput)
	}
	os.Exit(exitOK)
}

// ---------------------------------
// [NEW] URL収集ヘルパ
//   - infile == ""  : 位置引数をそのまま利用
//   - infile == "-" : 標準入力から1行1URLで受け取る
//   - それ以外     : 指定ファイルから読み込む
//     空行・#始まりの行は無視／重複は除去
//
// ---------------------------------
func collectURLs(args []string, infile string) ([]string, error) {
	if strings.TrimSpace(infile) == "" {
		return dedupe(args), nil
	}

	var r io.ReadCloser
	if infile == "-" {
		r = os.Stdin
	} else {
		f, err := os.Open(infile)
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", infile, err)
		}
		r = f
		defer func() {
			if err := r.Close(); err != nil {
				_ = err // lint対策：v0.1では黙殺
			}
		}()
	}

	sc := bufio.NewScanner(r)
	// 長い行対策でバッファ拡張（必要に応じて調整）
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

// [NEW] 重複除去（順序維持の単純実装）
func dedupe(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
