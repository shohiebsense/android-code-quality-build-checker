#### Show all issues (default)
./android-quality-checker ./my-project

#### Show only CRITICAL and HIGH issues
./android-quality-checker ./my-project --severity=HIGH

#### Show only CRITICAL issues
./android-quality-checker ./my-project --severity=CRITICAL

#### Show MEDIUM and above, save to file
./android-quality-checker ./my-project report.md --severity=MEDIUM

#### Show LOW and above (essentially all issues)
./android-quality-checker ./my-project --severity=LOW


#### Build for windows
GOOS=windows GOARCH=amd64 go build -o android-quality-checker.bin android-quality-checker.go