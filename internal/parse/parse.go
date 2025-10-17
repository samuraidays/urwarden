package parse

import (
	"errors"
	"net/url"
	"strings"

	"github.com/samuraidays/urwarden/internal/model"
)

// ---------------------------
// このファイルは URL の解析（Parse）と正規化（Normalize）を行うモジュール。
// 入力されたURL文字列を、scheme / host / tld / path / query に分解して
// 構造体 model.NormalizedURL として返す。
// ---------------------------

// 想定外のURLスキームを検出したときに返すエラー（例: ftp:// など）
var ErrInvalidScheme = errors.New("invalid scheme: only http/https are allowed")

// ホスト名が存在しない場合のエラー（例: https:// だけなど）
var ErrNoHost = errors.New("invalid url: host is empty")

// NormalizeURL は、文字列URLをパースして構造体にまとめる関数。
// 仕様（v0.1）では http と https 以外はエラー。
// 返り値: 正常時 → NormalizedURL構造体, 失敗時 → エラー。
func NormalizeURL(input string) (model.NormalizedURL, error) {

	// Go標準の url.Parse を使ってURLを構造体に分解。
	// エラー例：不正な文字やスキームがない場合など。
	u, err := url.Parse(input)
	if err != nil {
		return model.NormalizedURL{}, err
	}

	// scheme（http / https）を小文字化して取得
	scheme := strings.ToLower(u.Scheme)

	// 許可されるスキームは http / https のみ。
	// それ以外（ftp, file など）は無効。
	if scheme != "http" && scheme != "https" {
		return model.NormalizedURL{}, ErrInvalidScheme
	}

	// ホスト部分（例: "Bad.Example.com"）を小文字化して取得。
	// strings.Trim で先頭と末尾のドットを除去（"example.com." → "example.com"）
	host := strings.ToLower(strings.Trim(u.Hostname(), "."))

	// ホスト名が空（例: "https://" のような入力）はエラー。
	if host == "" {
		return model.NormalizedURL{}, ErrNoHost
	}

	// -------------------------------
	// v0.1仕様：シンプルなTLD抽出
	// -------------------------------
	// 例: host = "bad.example.com" → tld = "com"
	// ドメイン名の最後の "." 以降を取り出すだけの単純ルール。
	tld := host
	if i := strings.LastIndex(host, "."); i >= 0 && i+1 < len(host) {
		tld = host[i+1:]
	}

	// パス部分（"/login" など）を取得。
	// EscapedPath() は特殊文字（例: スペース）を %20 形式に変換してくれる。
	path := u.EscapedPath()

	// クエリ部分（"next=%2Fhome" など）を取得。
	query := u.RawQuery

	// 正規化されたURL情報を model.NormalizedURL 構造体にまとめて返す。
	return model.NormalizedURL{
		Scheme: scheme,
		Host:   host,
		TLD:    tld,
		Path:   path,
		Query:  query,
	}, nil
}
