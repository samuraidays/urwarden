package version

// これらの値は ldflags によってビルド時に上書きされる
var (
	Version     = "dev"     // Gitタグまたは describe の出力
	Commit      = "unknown" // 短いコミットID
	BuildDate   = "unknown" // UTC日付
	BuildNumber = "0"       // コミット数
)
