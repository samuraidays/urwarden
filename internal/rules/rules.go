package rules

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/samuraidays/urwarden/internal/model"
)

const (
	// ルール名（JSON出力でも使われる）
	RuleBlocklistHit     = "blocklist_hit"       // ブロックリスト一致
	RuleSuspiciousTLD    = "suspicious_tld"      // 怪しいTLD（ドメインの末尾）
	RulePathHasLoginLike = "path_has_login_like" // URLパスに「login」等を含む

	// 各ルールに対応する重み（スコア加点値）
	WeightBlocklistHit  = 70
	WeightSuspiciousTLD = 20
	WeightPathLoginLike = 10
)

// ---------------------------
// 固定リスト（v0.1の簡易ルール）
// ---------------------------

// 怪しいTLD（トップレベルドメイン）の一覧。
// これらがURLの末尾に含まれると、スコア +20。
var suspiciousTLD = map[string]struct{}{
	"xyz": {}, "top": {}, "click": {}, "help": {}, "shop": {},
	"live": {}, "cam": {}, "kim": {}, "fit": {}, "country": {},
}

// URL内に含まれると「ログイン誘導URL」と判断するキーワード。
// path + query（小文字化後）に含まれていれば +10。
var loginLikeTokens = []string{
	"login", "signin", "verify", "update", "password", "passcode",
	"secure", "confirm", "invoice", "billing",
}

// ---------------------------
// メイン関数: EvaluateAll
// ---------------------------
//
// 3つのルール（blocklist / suspicious_tld / path_has_login_like）を順に評価。
// 該当したルールの情報を model.Reason として reasons[] に追加し、返す。
//
// 引数:
//
//	n ... 正規化済みURL情報 (parse.NormalizeURLの出力)
//	blocklistPath ... ブロックリストファイルのパス（例: "data/blocklist.txt"）
//
// 戻り値:
//
//	[]model.Reason ... 該当ルールの一覧（空でもnilではない）
func EvaluateAll(n model.NormalizedURL, blocklistPath string) []model.Reason {
	// 3ルール分の結果を格納するスライス（最初は空）
	reasons := make([]model.Reason, 0, 3)

	// -------------------------------
	// Rule 1: blocklist_hit
	// -------------------------------
	// ローカルのブロックリストファイルに該当ドメインが載っていれば +70。
	if hit := blocklistHit(n.Host, blocklistPath); hit != "" {
		detail := hit
		if n.Host != hit && strings.HasSuffix(n.Host, "."+hit) {
			detail = "matched subdomain of " + hit
		}
		reasons = append(reasons, model.Reason{
			Rule:   RuleBlocklistHit,
			Weight: WeightBlocklistHit,
			Detail: detail, // どのドメインが一致したか
		})
	}

	// -------------------------------
	// Rule 2: suspicious_tld
	// -------------------------------
	// 怪しいTLDリストに含まれていれば +20。
	if _, ok := suspiciousTLD[strings.ToLower(n.TLD)]; ok {
		reasons = append(reasons, model.Reason{
			Rule:   RuleSuspiciousTLD,
			Weight: WeightSuspiciousTLD,
			Detail: n.TLD, // どのTLDに該当したか
		})
	}

	// -------------------------------
	// Rule 3: path_has_login_like
	// -------------------------------
	// パスやクエリに「login」「verify」などが含まれていれば +10。
	if matched := pathHasLoginLike(n.Path, n.Query); matched != "" {
		reasons = append(reasons, model.Reason{
			Rule:   RulePathHasLoginLike,
			Weight: WeightPathLoginLike,
			Detail: "matched: " + matched, // どのキーワードにマッチしたか
		})
	}

	return reasons
}

// ----------------------------------------
// 以下は各ルールの内部実装関数
// ----------------------------------------

// blocklistHit は指定されたホストがブロックリストに載っているか確認する。
// 載っていればそのドメイン文字列を返し、無ければ空文字("")を返す。
// ファイルが存在しなくてもエラーにはせず、そのままスキップ（v0.1仕様）。
func blocklistHit(host string, blocklistPath string) string {
	path := blocklistPath
	if path == "" {
		// デフォルトパス（指定が無ければ data/blocklist.txt を探す）
		path = "data/blocklist.txt"
	}

	// ファイルを開く（存在しない場合はerrが返る）
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		// ファイルが存在しないのは正常扱い（スコア加点しないだけ）
		return ""
	}
	defer func() {
		// deferで関数終了時に必ずファイルを閉じる
		if err := f.Close(); err != nil {
			// エラーが出てもv0.1では無視（ログ出力しない）
			_ = err
		}
	}()

	// bufio.Scanner は1行ずつテキストを読み込むのに便利な構造。
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text()) // 前後の空白除去

		// コメント行（#から始まる）や空行はスキップ。
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 形式例:
		//   "0.0.0.0 bad.example.com"
		//   "malicious.test"
		// どちらでも対応できるようにスペース区切りで最後の要素を取る。
		fields := strings.Fields(line)
		var dom string
		if len(fields) == 1 {
			dom = fields[0]
		} else {
			dom = fields[len(fields)-1]
		}

		// ドメインを小文字化し、末尾のドットを除去。
		dom = strings.ToLower(strings.Trim(dom, "."))

		// 完全一致で比較（サブドメインは v0.1 では無視）。
		if dom == host {
			return dom // 一致したら即リターン
		}
		// サブドメイン一致（例: host=sub.bad.example.com, dom=example.com）
		if strings.HasSuffix(host, "."+dom) {
			// 返却値の書式は好みでOK。ここではわかりやすく prefix を付けない。
			// detail に "matched subdomain of <dom>" を出したい場合は呼び出し側で整形してもよい。
			return dom
		}
	}

	// スキャン中にエラーがあっても無視（簡易仕様のため）
	return ""
}

// pathHasLoginLike は、pathとqueryを連結して
// 「login」「verify」「update」などの文字列が含まれているかを確認。
// 含まれていればマッチしたキーワードを返す。
func pathHasLoginLike(path, query string) string {
	// パスとクエリを小文字に変換して結合。
	s := strings.ToLower(path)
	if query != "" {
		s += "?" + strings.ToLower(query)
	}

	// loginLikeTokens のいずれかが含まれていればマッチ。
	for _, t := range loginLikeTokens {
		if strings.Contains(s, t) {
			return t // 最初に見つかった単語を返す
		}
	}
	return "" // 該当なし
}
