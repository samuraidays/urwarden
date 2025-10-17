package main

import (
	"fmt"
	"os"

	// 内部パッケージをインポート
	"github.com/samuraidays/urwarden/internal/output" // JSON出力
	"github.com/samuraidays/urwarden/internal/parse"  // URLの分解・正規化
	"github.com/samuraidays/urwarden/internal/rules"  // 判定ルール（blocklistやTLDなど）
	"github.com/samuraidays/urwarden/internal/score"  // スコア集計とラベル付け
)

const (
	exitOK       = 0 // 正常終了
	exitInternal = 1 // 内部エラー（ファイルI/Oや想定外の例外）
	exitInput    = 2 // 入力エラー（URL不正など）
)

func main() {
	// os.Args にはコマンドライン引数が格納されている。
	// 例: 「urwarden https://example.com」
	if len(os.Args) < 2 {
		// 引数が足りない場合はエラーを表示して終了
		fmt.Fprintln(os.Stderr, "Usage: urwarden <URL>")
		os.Exit(exitInput)
	}

	// 引数の1つ目をURLとして取得
	inputURL := os.Args[1]

	// -------------------------------
	// 1) URLをパースして正規化
	// -------------------------------
	// parse.NormalizeURL は、URLを分解して
	//   scheme (http/https)
	//   host (ドメイン)
	//   tld  (トップレベルドメイン)
	//   path, query
	// などを整形して返す。
	norm, err := parse.NormalizeURL(inputURL)
	if err != nil {
		// もし不正なURL（例: ftp://やスキームなし）ならここで終了
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(exitInput)
	}

	// -------------------------------
	// 2) 3つのルールを評価
	// -------------------------------
	// EvaluateAll は次の3つの簡易ルールを適用して「理由リスト（reasons）」を返す。
	//   - blocklist_hit: ドメインがブロックリストに載っていれば +70点
	//   - suspicious_tld: 怪しいTLD（.xyzなど）なら +20点
	//   - path_has_login_like: パスに "login" 等が含まれていれば +10点
	// data/blocklist.txt が存在しなくても panic せずにスキップする。
	reasons := rules.EvaluateAll(norm, "data/blocklist.txt")

	// -------------------------------
	// 3) スコア集計とラベル判定
	// -------------------------------
	// 各ルールの weight を合計してスコアを算出し、
	// スコアに応じて label を決定する。
	//   score >= 70 → malicious
	//   score >= 30 → suspicious
	//   それ以外   → benign
	total, label := score.Aggregate(reasons)

	// -------------------------------
	// 4) JSON形式で結果を出力
	// -------------------------------
	// output.WriteResultJSON は結果を構造体にまとめて
	//   {
	//     "input_url": "...",
	//     "normalized": {...},
	//     "score": 80,
	//     "label": "malicious",
	//     "reasons": [...],
	//     "timestamp": "2025-10-17T00:00:00Z"
	//   }
	// のように標準出力へ書き出す。
	if err := output.WriteResultJSON(inputURL, norm, total, label, reasons); err != nil {
		// JSON出力に失敗した場合（例: 権限やI/Oエラーなど）
		fmt.Fprintln(os.Stderr, "failed to write json:", err.Error())
		os.Exit(exitInternal)
	}

	// -------------------------------
	// 5) 正常終了
	// -------------------------------
	os.Exit(exitOK)
}
