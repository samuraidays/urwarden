package score

import "github.com/samuraidays/urwarden/internal/model"

// ------------------------------------------------------
// このファイルは「スコア計算とラベル判定」を担当するパッケージ。
// 各ルール（blocklist, TLD, pathなど）で得た加点を合計し、
// 合計値に応じて「安全／疑わしい／悪意あり」を分類する。
// ------------------------------------------------------

// Aggregate は、reasons（検出理由一覧）を受け取り、
// それぞれの Weight（加点値）を合計して「総スコア」と「ラベル」を返す。
//
// 返り値:
//   - int: 合計スコア（例: 80）
//   - string: ラベル文字列（"benign" / "suspicious" / "malicious"）
func Aggregate(reasons []model.Reason) (int, string) {
	total := 0 // 合計スコアを格納する変数

	// reasons の中には各ルールで検出された項目が入っている。
	// たとえば:
	//   [{rule:blocklist_hit, weight:70}, {rule:path_has_login_like, weight:10}]
	// それぞれの weight を足し合わせて総スコアを出す。
	for _, r := range reasons {
		total += r.Weight
	}

	// スコアに応じたラベル（判定結果）を求める
	label := labelOf(total)

	return total, label
}

// labelOf は、数値スコアを受け取り、
// その値に応じて3段階のラベルを返す単純な判定関数。
//
// スコアの基準（v0.1仕様）:
//   - 70点以上 → "malicious"（悪意あり）
//   - 30点以上 → "suspicious"（疑わしい）
//   - それ未満 → "benign"（安全）
func labelOf(score int) string {
	switch {
	case score >= 70:
		return "malicious"
	case score >= 30:
		return "suspicious"
	default:
		return "benign"
	}
}
