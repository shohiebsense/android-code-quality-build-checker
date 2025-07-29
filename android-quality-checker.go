package main

import (
	"bufio"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

type QualityIssue struct {
	File        string
	Line        int
	Type        string
	Description string
	Severity    string
}

type CodeQualityChecker struct {
	issues []QualityIssue
	stats  map[string]int
}

func NewCodeQualityChecker() *CodeQualityChecker {
	return &CodeQualityChecker{
		issues: make([]QualityIssue, 0),
		stats:  make(map[string]int),
	}
}

func (c *CodeQualityChecker) addIssue(file string, line int, issueType, description, severity string) {
	c.issues = append(c.issues, QualityIssue{
		File:        file,
		Line:        line,
		Type:        issueType,
		Description: description,
		Severity:    severity,
	})
	c.stats[severity]++
}

func (c *CodeQualityChecker) checkFile(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0

	// Patterns for different checks
	debugPatterns := []*regexp.Regexp{
		regexp.MustCompile(`console\.log\(`),
		regexp.MustCompile(`System\.out\.print`),
		regexp.MustCompile(`Log\.[dviwe]\(`),
		regexp.MustCompile(`println\(`),
		regexp.MustCompile(`debugger;`),
	}

	commentedCodePattern := regexp.MustCompile(`^\s*//.*[{}();].*$`)
	todoPattern := regexp.MustCompile(`(?i)//.*(?:todo|fixme|hack|xxx)`)
	longLinePattern := regexp.MustCompile(`.{120,}`)
	hardcodedStringPattern := regexp.MustCompile(`"(?:password|key|token|secret|api_key)"\s*[:=]`)

	var inBlockComment bool
	var functionLength int
	var currentFunction string

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmedLine := strings.TrimSpace(line)

		// Skip empty lines
		if trimmedLine == "" {
			continue
		}

		// Track block comments
		if strings.Contains(line, "/*") {
			inBlockComment = true
		}
		if strings.Contains(line, "*/") {
			inBlockComment = false
			continue
		}
		if inBlockComment {
			continue
		}

		// Check for debugging artifacts
		for _, pattern := range debugPatterns {
			if pattern.MatchString(line) {
				c.addIssue(filePath, lineNum, "Debug Artifact", 
					"Remove debugging statement", "HIGH")
			}
		}

		// Check for commented-out code
		if commentedCodePattern.MatchString(line) {
			c.addIssue(filePath, lineNum, "Commented Code", 
				"Remove commented-out code", "MEDIUM")
		}

		// Check for TODO/FIXME comments
		if todoPattern.MatchString(line) {
			c.addIssue(filePath, lineNum, "TODO/FIXME", 
				"Address TODO/FIXME comment", "LOW")
		}

		// Check line length
		if longLinePattern.MatchString(line) {
			c.addIssue(filePath, lineNum, "Long Line", 
				fmt.Sprintf("Line too long (%d chars)", len(line)), "LOW")
		}

		// Check for hardcoded secrets
		if hardcodedStringPattern.MatchString(strings.ToLower(line)) {
			c.addIssue(filePath, lineNum, "Security", 
				"Potential hardcoded secret detected", "CRITICAL")
		}

		// Track function length (simplified)
		if strings.Contains(line, "function ") || strings.Contains(line, "def ") || 
		   regexp.MustCompile(`\w+\s*\([^)]*\)\s*\{`).MatchString(line) {
			if functionLength > 50 {
				c.addIssue(filePath, lineNum-functionLength, "Code Quality", 
					fmt.Sprintf("Function '%s' is too long (%d lines)", currentFunction, functionLength), "MEDIUM")
			}
			functionLength = 1
			currentFunction = extractFunctionName(line)
		} else if strings.Contains(line, "{") || strings.Contains(line, "}") {
			functionLength++
		}

		// Check naming conventions (simplified)
		if strings.Contains(line, "var ") || strings.Contains(line, "let ") || strings.Contains(line, "const ") {
			varName := extractVariableName(line)
			if varName != "" && !isValidNaming(varName) {
				c.addIssue(filePath, lineNum, "Naming Convention", 
					fmt.Sprintf("Variable '%s' doesn't follow naming conventions", varName), "LOW")
			}
		}
	}

	return scanner.Err()
}

func extractFunctionName(line string) string {
	// Simplified function name extraction
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`function\s+(\w+)`),
		regexp.MustCompile(`def\s+(\w+)`),
		regexp.MustCompile(`(\w+)\s*\([^)]*\)\s*\{`),
	}

	for _, pattern := range patterns {
		matches := pattern.FindStringSubmatch(line)
		if len(matches) > 1 {
			return matches[1]
		}
	}
	return "unknown"
}

func extractVariableName(line string) string {
	pattern := regexp.MustCompile(`(?:var|let|const)\s+(\w+)`)
	matches := pattern.FindStringSubmatch(line)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func isValidNaming(name string) bool {
	// Check for camelCase (simplified)
	camelCase := regexp.MustCompile(`^[a-z][a-zA-Z0-9]*$`)
	// Check for CONSTANT_CASE
	constantCase := regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

	return camelCase.MatchString(name) || constantCase.MatchString(name)
}

func (c *CodeQualityChecker) checkAndroidSpecific(projectPath string) {
	// Check for common Android issues

	// Check AndroidManifest.xml
	manifestPath := filepath.Join(projectPath, "app", "src", "main", "AndroidManifest.xml")
	if _, err := os.Stat(manifestPath); err == nil {
		c.checkManifest(manifestPath)
	}

	// Check build.gradle files
	filepath.WalkDir(projectPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		if d.IsDir() && shouldSkipDir(d.Name()) {
			return fs.SkipDir
		}

		if d.Name() == "build.gradle" || d.Name() == "build.gradle.kts" {
			c.checkBuildGradle(path)
		}

		return nil
	})
}

func (c *CodeQualityChecker) checkManifest(manifestPath string) {
	file, err := os.Open(manifestPath)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Check for debug permissions in release
		if strings.Contains(line, "android.permission.WRITE_EXTERNAL_STORAGE") {
			c.addIssue(manifestPath, lineNum, "Android Security", 
				"Consider using scoped storage instead of WRITE_EXTERNAL_STORAGE", "MEDIUM")
		}

		if strings.Contains(line, `android:debuggable="true"`) {
			c.addIssue(manifestPath, lineNum, "Android Security", 
				"Remove debuggable=true for production builds", "HIGH")
		}

		if strings.Contains(line, `android:allowBackup="true"`) {
			c.addIssue(manifestPath, lineNum, "Android Security", 
				"Consider setting allowBackup=false for sensitive apps", "MEDIUM")
		}
	}
}

func (c *CodeQualityChecker) checkBuildGradle(gradlePath string) {
	file, err := os.Open(gradlePath)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Check for outdated dependencies (simplified)
		if strings.Contains(line, "compile ") && !strings.Contains(line, "//") {
			c.addIssue(gradlePath, lineNum, "Deprecated", 
				"Replace 'compile' with 'implementation' or 'api'", "MEDIUM")
		}

		// Check for version pinning
		if regexp.MustCompile(`implementation.*\+`).MatchString(line) {
			c.addIssue(gradlePath, lineNum, "Dependency Management", 
				"Avoid using '+' in version numbers, pin to specific versions", "MEDIUM")
		}
	}
}

func (c *CodeQualityChecker) scanProject(projectPath string) error {
	fmt.Printf("Scanning project: %s", projectPath)

	fileCount := 0
	return filepath.WalkDir(projectPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // Continue on errors
		}

		// Skip certain directories
		if d.IsDir() {
			dirName := d.Name()
			if dirName == ".git" || dirName == "node_modules" || 
			   dirName == "build" || dirName == ".gradle" {
				return fs.SkipDir
			}
			return nil
		}

		// Check relevant file types
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".java" || ext == ".kt" || ext == ".js" || ext == ".ts" || 
		   ext == ".xml" || ext == ".gradle" {
			fileCount++
			if fileCount%10 == 0 {
				fmt.Printf("Processed %d files...", fileCount)
			}
			return c.checkFile(path)
		}

		return nil
	})
}

func getSeverityEmoji(severity string) string {
	switch severity {
	case "CRITICAL":
		return "🔴"
	case "HIGH":
		return "🟠"
	case "MEDIUM":
		return "🟡"
	case "LOW":
		return "🟢"
	default:
		return "🔵"
	}
}

func getSeverityPriority(severity string) int {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

// Fix the filtering function
func shouldIncludeIssue(issueSeverity, minSeverity string) bool {
	if minSeverity == "" {
		return true // Show all if no filter specified
	}
	
	// Convert to uppercase for comparison
	issueSev := strings.ToUpper(issueSeverity)
	minSev := strings.ToUpper(minSeverity)
	
	return getSeverityPriority(issueSev) >= getSeverityPriority(minSev)
}

func calculateQualityScore(stats map[string]int, total int) string {
	if total == 0 {
		return "100/100 ⭐⭐⭐⭐⭐"
	}

	score := 100
	score -= stats["CRITICAL"] * 20
	score -= stats["HIGH"] * 10
	score -= stats["MEDIUM"] * 5
	score -= stats["LOW"] * 2

	if score < 0 {
		score = 0
	}

	stars := ""
	starCount := score / 20
	for i := 0; i < starCount; i++ {
		stars += "⭐"
	}

	return fmt.Sprintf("%d/100 %s", score, stars)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: android-quality-checker <project-path> [output-file] [--severity=LEVEL]")
		fmt.Println("Example: android-quality-checker ./my-android-project")
		fmt.Println("Example: android-quality-checker ./my-android-project quality-report.md")
		fmt.Println("Example: android-quality-checker ./my-android-project --severity=HIGH")
		fmt.Println("Example: android-quality-checker ./my-android-project report.md --severity=MEDIUM")
		fmt.Println("")
		fmt.Println("Severity levels: CRITICAL, HIGH, MEDIUM, LOW")
		fmt.Println("Default: Shows all issues")
		os.Exit(1)
	}
	projectPath := os.Args[1]
	outputFile := ""
	minSeverity := ""

	for i := 2; i < len(os.Args); i++ {
		arg := os.Args[i]
		if strings.HasPrefix(arg, "--severity=") {
			minSeverity = strings.TrimPrefix(arg, "--severity=")
		} else if outputFile == "" {
			outputFile = arg
		}
	}
	
	// Check if path exists
	if _, err := os.Stat(projectPath); os.IsNotExist(err) {
		fmt.Printf("Error: Project path '%s' does not exist\n", projectPath)
		os.Exit(1)
	}

	fmt.Println("🚀 Android Code Quality Checker")
	fmt.Println("================================")

	checker := NewCodeQualityChecker()

	fmt.Println("Checking local.properties...")
	checker.checkLocalPropertiesFile(projectPath+"/local.properties")
	
	checker.checkProductionReadiness(projectPath)

	// Scan the project
	if err := checker.scanProject(projectPath); err != nil {
		fmt.Printf("Error scanning project: %v\n", err)
		os.Exit(1)
	}
	
	// Run Android-specific checks
	fmt.Println("Running Android-specific checks...")
	checker.checkAndroidSpecific(projectPath)
	

	branch := getCurrentGitBranch(projectPath)
	if branch != "" {
		fmt.Printf("Current Git branch: %s\n", branch)
	} else {
		fmt.Println("Not a git repository or unable to determine branch.")
	}

	if branch == "" {
		branch = "NOT IN A GIT REPOSITORY"
	}
	

	// Generate markdown report with severity filter
	fmt.Println("Generating report...")
	report := checker.generateMarkdownReportWithFilter(minSeverity, branch)
	
	
	// Output report
	if outputFile != "" {
		err := os.WriteFile(outputFile, []byte(report), 0644)
		if err != nil {
			fmt.Printf("Error writing to file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✅ Report saved to: %s\n", outputFile)
	} else {
		fmt.Println("\n" + report)
	}
	
	fmt.Println("🎉 Quality check complete!")
}

func (c *CodeQualityChecker) checkLocalPropertiesFile(filePath string) {
	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		c.addIssue(filePath, 0, "Missing File", 
			"local.properties file not found - required for Android development", "HIGH")
		return
	}
	
	file, err := os.Open(filePath)
	if err != nil {
		c.addIssue(filePath, 0, "File Access", 
			"Cannot read local.properties file", "MEDIUM")
		return
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	lineNum := 0
	hasContent := false
	
	// Track required properties
	requiredProps := map[string]bool{
		"sdk.dir":           false,
		"MAPS_SDK_API_KEY":  false,
		"E_KEY":             false,
		"prefix":            false,
		"key_chiper":        false,
	}
	
	// Track optional properties
	optionalProps := map[string]bool{
		"ndk.dir": false,
	}
	
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		hasContent = true
		
		// Check if line contains a property
		if strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				log.Println(parts[0])
				log.Println(parts[1])
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				
				// Check required properties
				if _, exists := requiredProps[key]; exists {
					requiredProps[key] = true
					if value == "" {
						severity := "CRITICAL"
						c.addIssue(filePath, lineNum, "Empty Required Property", 
							fmt.Sprintf("Required property '%s' is empty", key), severity)
					} else {
						// Additional validation for specific keys
						c.validatePropertyValue(filePath, lineNum, key, value)
					}
				}
				
				// Check optional properties
				if _, exists := optionalProps[key]; exists {
					optionalProps[key] = true
					if value == "" {
						c.addIssue(filePath, lineNum, "Empty Property", 
							fmt.Sprintf("Property '%s' has empty value", key), "MEDIUM")
					}
				}
				
				// Check for any other empty properties
				if value == "" && !requiredProps[key] && !optionalProps[key] {
					c.addIssue(filePath, lineNum, "Empty Property", 
						fmt.Sprintf("Property '%s' has empty value", key), "LOW")
				}
			}
		}
	}
	
	// Check if file is completely empty
	if !hasContent {
		c.addIssue(filePath, 0, "Empty File", 
			"local.properties file is empty - should contain required properties", "HIGH")
		return
	}
	
	// Check for missing required properties
	for prop, found := range requiredProps {
		log.Println(prop + " ", found)
		if !found {
			severity := "CRITICAL"
			description := fmt.Sprintf("Missing required property '%s'", prop)
			
			switch prop {
			case "sdk.dir":
				description = "Missing sdk.dir property - Android SDK path required for builds"
			case "MAPS_SDK_API_KEY":
				description = "Missing MAPS_SDK_API_KEY - required for Google Maps integration"
			case "E_KEY":
				description = "Missing E_KEY - required for encryption functionality"
			case "prefix":
				description = "Missing prefix - required for app configuration"
			case "key_chiper":
				description = "Missing key_chiper - required for cipher operations"
			}
			
			c.addIssue(filePath, 0, "Missing Required Property", description, severity)
		}
	}
	
	if err := scanner.Err(); err != nil {
		c.addIssue(filePath, 0, "File Read Error", 
			"Error reading local.properties file", "MEDIUM")
	}
}

// Add this new function for additional property validation
func (c *CodeQualityChecker) validatePropertyValue(filePath string, lineNum int, key, value string) {
	switch key {
	case "sdk.dir":
		// Check if SDK directory path looks valid
		if !strings.Contains(value, "Android") && !strings.Contains(value, "sdk") {
			c.addIssue(filePath, lineNum, "Invalid SDK Path", 
				"SDK path doesn't appear to be valid Android SDK directory", "MEDIUM")
		}
		
	case "MAPS_SDK_API_KEY":
		// Check if API key format looks valid (Google API keys are typically 39 chars)
		if len(value) < 20 {
			c.addIssue(filePath, lineNum, "Invalid API Key", 
				"MAPS_SDK_API_KEY appears to be too short for a valid Google API key", "MEDIUM")
		}
		if strings.Contains(value, "your_api_key") || strings.Contains(value, "placeholder") {
			c.addIssue(filePath, lineNum, "Placeholder API Key", 
				"MAPS_SDK_API_KEY contains placeholder value", "HIGH")
		}
		
	case "E_KEY", "key_chiper":
		// Check for common placeholder values
		if strings.Contains(strings.ToLower(value), "test") || 
		   strings.Contains(strings.ToLower(value), "demo") ||
		   strings.Contains(strings.ToLower(value), "placeholder") {
			c.addIssue(filePath, lineNum, "Test/Demo Key", 
				fmt.Sprintf("%s appears to contain test/demo value", key), "MEDIUM")
		}
		
	case "prefix":
		// Check if prefix is reasonable length
		if len(value) < 2 {
			c.addIssue(filePath, lineNum, "Short Prefix", 
				"Prefix value appears to be too short", "LOW")
		}
	}
}

func (c *CodeQualityChecker) generateMarkdownReportWithFilter(minSeverity string, branchName string) string {
	var report strings.Builder

	// Filter issues based on minimum severity
	filteredIssues := make([]QualityIssue, 0)
	filteredStats := make(map[string]int)
	
	// Debug: Print filtering info
	fmt.Printf("Filtering with minimum severity: '%s'\n", minSeverity)
	
	for _, issue := range c.issues {
		shouldInclude := shouldIncludeIssue(issue.Severity, minSeverity)
		fmt.Printf("Issue: %s (severity: %s) -> Include: %t\n", issue.Type, issue.Severity, shouldInclude)
		
		if shouldInclude {
			filteredIssues = append(filteredIssues, issue)
			filteredStats[issue.Severity]++
		}
	}
	
	fmt.Printf("Original issues: %d, Filtered issues: %d\n", len(c.issues), len(filteredIssues))
	fmt.Printf("Filtered stats: %+v\n", filteredStats)

	// Header
	report.WriteString("# 🔍 Android Code Quality Report\n\n")
	report.WriteString(fmt.Sprintf("_Generated: %s_\n", time.Now().Format("2006-01-02 15:04:05")))
	report.WriteString("\n\n")
	report.WriteString(fmt.Sprintf("_Branch: %s_\n", branchName))
	report.WriteString("\n\n")
	if minSeverity != "" {
		report.WriteString(fmt.Sprintf("_Filtered: %s and above_\n", strings.ToUpper(minSeverity)))
	}
	report.WriteString("\n")

	// Summary
	total := len(filteredIssues)
	originalTotal := len(c.issues)
	qualityScore := calculateQualityScore(filteredStats, total)
	
	report.WriteString("## 📊 Summary\n\n")
	if minSeverity != "" {
		report.WriteString(fmt.Sprintf("- **Filtered Issues:** %d (of %d total)\n", total, originalTotal))
	} else {
		report.WriteString(fmt.Sprintf("- **Total Issues:** %d\n", total))
	}
	report.WriteString(fmt.Sprintf("- **Quality Score:** %s\n\n", qualityScore))

	if total == 0 {
		if minSeverity != "" {
			report.WriteString(fmt.Sprintf("### ✅ No %s+ Issues Found!\n\n", strings.ToUpper(minSeverity)))
			if originalTotal > 0 {
				report.WriteString(fmt.Sprintf("There are %d lower severity issues that were filtered out.\n\n", originalTotal))
			}
		} else {
			report.WriteString("### ✅ Excellent!\n\nNo issues found! Your code meets all quality standards.\n\n")
		}
		return report.String()
	}

	// Issues by severity - ONLY show severities that have filtered issues
	report.WriteString("## 🚩 Issues to Fix\n\n")
	
	// Get only severities that exist in filtered issues (in priority order)
	severityOrder := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"}
	
	for _, severity := range severityOrder {
		count := filteredStats[severity]
		if count == 0 {
			continue // Skip severities with no issues
		}
		
		// Get issues for this severity
		severityIssues := make([]QualityIssue, 0)
		for _, issue := range filteredIssues {
			if strings.ToUpper(issue.Severity) == severity {
				severityIssues = append(severityIssues, issue)
			}
		}
		
		if len(severityIssues) == 0 {
			continue
		}
		
		report.WriteString(fmt.Sprintf("### %s %s (%d issues)\n\n", getSeverityEmoji(severity), severity, len(severityIssues)))
		
		for _, issue := range severityIssues {
			report.WriteString(fmt.Sprintf("**File:** `%s`  \n", issue.File))
			report.WriteString(fmt.Sprintf("**Line:** %d  \n", issue.Line))
			report.WriteString(fmt.Sprintf("**Type:** %s  \n", issue.Type))
			report.WriteString(fmt.Sprintf("**Description:** %s\n\n", issue.Description))
			report.WriteString("---\n\n")
		}
	}

	// Recommendations - ONLY show recommendations for existing severities
	report.WriteString("## 💡 Recommendations\n\n")
	if filteredStats["CRITICAL"] > 0 {
		report.WriteString("- **Fix all CRITICAL issues immediately.**\n")
	}
	if filteredStats["HIGH"] > 0 {
		report.WriteString("- **Fix all HIGH issues before release.**\n")
	}
	if filteredStats["MEDIUM"] > 0 {
		report.WriteString("- **Address MEDIUM issues soon.**\n")
	}
	if filteredStats["LOW"] > 0 {
		report.WriteString("- **Consider fixing LOW issues for better code quality.**\n")
	}
	
	if minSeverity != "" && originalTotal > total {
		report.WriteString(fmt.Sprintf("\n_Note: %d lower severity issues were filtered out. Run without --severity flag to see all issues._\n", originalTotal-total))
	}
	
	report.WriteString("\n---\n")
	report.WriteString("_Generated by Android Code Quality Checker_\n")

	return report.String()
}

func getCurrentGitBranch(projectPath string) string {
	// Try different Git command variations for cross-platform compatibility
	gitCommands := [][]string{
		{"git", "-C", projectPath, "rev-parse", "--abbrev-ref", "HEAD"},
		{"git.exe", "-C", projectPath, "rev-parse", "--abbrev-ref", "HEAD"},
	}
	
	// On Windows, also try with cmd wrapper
	if runtime.GOOS == "windows" {
		gitCommands = append(gitCommands, 
			[]string{"cmd", "/C", "git", "-C", projectPath, "rev-parse", "--abbrev-ref", "HEAD"})
	}
	
	for _, cmdArgs := range gitCommands {
		cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
		output, err := cmd.Output()
		if err == nil {
			return strings.TrimSpace(string(output))
		}
	}
	
	// Fallback: try reading .git/HEAD directly
	return readGitHeadFile(projectPath)
}

func readGitHeadFile(projectPath string) string {
	headFile := filepath.Join(projectPath, ".git", "HEAD")
	content, err := os.ReadFile(headFile)
	if err != nil {
		return "unknown"
	}
	
	headContent := strings.TrimSpace(string(content))
	if strings.HasPrefix(headContent, "ref: refs/heads/") {
		return strings.TrimPrefix(headContent, "ref: refs/heads/")
	}
	
	// If HEAD is detached, return short commit hash
	if len(headContent) >= 8 {
		return "detached-" + headContent[:8]
	}
	
	return "unknown"
}

func (c *CodeQualityChecker) checkProductionReadiness(projectPath string) {
	fmt.Println("Checking production readiness...")
	
	// Check build.gradle files for production settings
	c.checkBuildConfiguration(projectPath)
	
	// Check for base URLs in code files
	c.checkBaseUrls(projectPath)
	
	// Check for HTTP debugging tools
	c.checkHttpDebugging(projectPath)
	
	// Check for debug modes and accessibility
	c.checkDebugModes(projectPath)
	
	// Check for hardcoded values
	c.checkHardcodedValues(projectPath)
}

// Check build.gradle for production configuration
func (c *CodeQualityChecker) checkBuildConfiguration(projectPath string) {
	filepath.WalkDir(projectPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		if d.IsDir() && shouldSkipDir(d.Name()) {
			return fs.SkipDir
		}
		
		
		if d.Name() == "build.gradle" || d.Name() == "build.gradle.kts" {
			c.analyzeBuildGradle(path)
		}
		
		return nil
	})
}

func (c *CodeQualityChecker) analyzeBuildGradle(gradlePath string) {
	file, err := os.Open(gradlePath)
	if err != nil {
		return
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	lineNum := 0
	inReleaseBlock := false
	
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		
		// Track build type blocks
		if strings.Contains(line, "release {") {
			inReleaseBlock = true
		} else if strings.Contains(line, "debug {") {
		} else if line == "}" {
			inReleaseBlock = false
		}
		
		// Check for production build settings
		if inReleaseBlock {
			if strings.Contains(line, "debuggable true") {
				c.addIssue(gradlePath, lineNum, "Production Config", 
					"Release build should not be debuggable", "CRITICAL")
			}
			
			if !strings.Contains(line, "minifyEnabled true") && strings.Contains(line, "minifyEnabled") {
				c.addIssue(gradlePath, lineNum, "Production Config", 
					"Release build should enable code minification", "HIGH")
			}
			
			if !strings.Contains(line, "shrinkResources true") && strings.Contains(line, "shrinkResources") {
				c.addIssue(gradlePath, lineNum, "Production Config", 
					"Release build should enable resource shrinking", "MEDIUM")
			}
		}
		
		// Check for HTTP debugging dependencies
		httpDebugDeps := []string{
			"com.github.chuckerteam.chucker",
			"com.facebook.flipper",
			"com.facebook.stetho",
			"com.squareup.leakcanary",
			"com.readystatesoftware.chuck",
		}
		
		for _, dep := range httpDebugDeps {
			if strings.Contains(line, dep) && !strings.Contains(line, "debugImplementation") {
				c.addIssue(gradlePath, lineNum, "HTTP Debugger", 
					fmt.Sprintf("HTTP debugging tool '%s' should only be in debugImplementation", dep), "HIGH")
			}
		}
		
		// Check for logging dependencies in release
		loggingDeps := []string{
			"com.jakewharton.timber",
			"org.slf4j",
		}
		
		for _, dep := range loggingDeps {
			if strings.Contains(line, dep) && strings.Contains(line, "implementation") && !strings.Contains(line, "debugImplementation") {
				c.addIssue(gradlePath, lineNum, "Logging Dependency", 
					fmt.Sprintf("Logging library '%s' should be debugImplementation only", dep), "MEDIUM")
			}
		}
	}
}

func shouldSkipDir(name string) bool {
	skipDirs := []string{".git", "node_modules", "build", ".gradle", "out", ".idea"}
	for _, skip := range skipDirs {
		if name == skip {
			return true
		}
	}
	return false
}
// Check for base URLs in source code
func (c *CodeQualityChecker) checkBaseUrls(projectPath string) {
	filepath.WalkDir(projectPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		
		if d.IsDir() && shouldSkipDir(d.Name()) {
			return fs.SkipDir
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".java" || ext == ".kt" || ext == ".xml" {
			c.analyzeBaseUrls(path)
		}
		
		return nil
	})
}

func (c *CodeQualityChecker) analyzeBaseUrls(filePath string) {
	file, err := os.Open(filePath)
	if err != nil {
		return
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	lineNum := 0
	
	// Patterns for non-production URLs
	nonProdPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)https?://.*localhost`),
		regexp.MustCompile(`(?i)https?://.*127\.0\.0\.1`),
		regexp.MustCompile(`(?i)https?://.*192\.168\.`),
		regexp.MustCompile(`(?i)https?://.*10\.0\.`),
		regexp.MustCompile(`(?i)https?://.*\.local`),
		regexp.MustCompile(`(?i)https?://.*staging`),
		regexp.MustCompile(`(?i)https?://.*test`),
		regexp.MustCompile(`(?i)https?://.*dev`),
		regexp.MustCompile(`(?i)https?://.*debug`),
		regexp.MustCompile(`(?i)base_?url.*=.*"https?://.*(?:localhost|127\.0\.0\.1|staging|test|dev)`),
	}
	
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		
		for _, pattern := range nonProdPatterns {
			if pattern.MatchString(line) {
				c.addIssue(filePath, lineNum, "Non-Production URL", 
					"Base URL appears to be non-production (localhost/staging/test)", "CRITICAL")
			}
		}
		
		// Check for hardcoded URLs that should be configurable
		urlPattern := regexp.MustCompile(`"https?://[^"]+\.com[^"]*"`)
		if urlPattern.MatchString(line) && !strings.Contains(line, "//") {
			c.addIssue(filePath, lineNum, "Hardcoded URL", 
				"URL should be configurable, not hardcoded", "MEDIUM")
		}
	}
}

// Check for HTTP debugging tools in code
func (c *CodeQualityChecker) checkHttpDebugging(projectPath string) {
	filepath.WalkDir(projectPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		if d.IsDir() && shouldSkipDir(d.Name()) {
			return fs.SkipDir
		}
		
		
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".java" || ext == ".kt" {
			c.analyzeHttpDebugging(path)
		}
		
		return nil
	})
}

func (c *CodeQualityChecker) analyzeHttpDebugging(filePath string) {
	file, err := os.Open(filePath)
	if err != nil {
		return
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	lineNum := 0
	
	// HTTP debugging patterns
	debugPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)chucker`),
		regexp.MustCompile(`(?i)flipper`),
		regexp.MustCompile(`(?i)stetho`),
		regexp.MustCompile(`(?i)leakcanary`),
		regexp.MustCompile(`(?i)chuck`),
		regexp.MustCompile(`(?i)httploggininterceptor`),
		regexp.MustCompile(`(?i)\.addInterceptor.*logging`),
	}
	
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		
		// Skip comments
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		
		for _, pattern := range debugPatterns {
			if pattern.MatchString(line) {
				c.addIssue(filePath, lineNum, "HTTP Debugger", 
					"HTTP debugging tool found - should be removed for production", "HIGH")
			}
		}
	}
}

// Check for debug modes and accessibility
func (c *CodeQualityChecker) checkDebugModes(projectPath string) {
	filepath.WalkDir(projectPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		
		if d.IsDir() && shouldSkipDir(d.Name()) {
			return fs.SkipDir
		}
		

		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".java" || ext == ".kt" || ext == ".xml" {
			c.analyzeDebugModes(path)
		}
		
		return nil
	})
}

func (c *CodeQualityChecker) analyzeDebugModes(filePath string) {
	file, err := os.Open(filePath)
	if err != nil {
		return
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	lineNum := 0
	
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		
		// Skip comments
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		
		// Check for debug flags
		debugPatterns := []struct {
			pattern     *regexp.Regexp
			description string
			severity    string
		}{
			{regexp.MustCompile(`(?i)BuildConfig\.DEBUG`), "BuildConfig.DEBUG usage found", "MEDIUM"},
			{regexp.MustCompile(`(?i)\.setDebug\(true\)`), "Debug mode explicitly enabled", "HIGH"},
			{regexp.MustCompile(`(?i)debug\s*=\s*true`), "Debug flag set to true", "HIGH"},
			{regexp.MustCompile(`(?i)isDebuggable\(\)`), "Debuggable check found", "LOW"},
			{regexp.MustCompile(`(?i)gesture.*debug`), "Gesture debugging enabled", "MEDIUM"},
			{regexp.MustCompile(`(?i)accessibility.*debug`), "Accessibility debugging enabled", "MEDIUM"},
			{regexp.MustCompile(`(?i)StrictMode`), "StrictMode usage found", "MEDIUM"},
		}
		
		for _, dp := range debugPatterns {
			if dp.pattern.MatchString(line) {
				c.addIssue(filePath, lineNum, "Debug Mode", dp.description, dp.severity)
			}
		}
	}
}

// Check for hardcoded values
func (c *CodeQualityChecker) checkHardcodedValues(projectPath string) {
	filepath.WalkDir(projectPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		
		if d.IsDir() && shouldSkipDir(d.Name()) {
			return fs.SkipDir
		}
		

		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".java" || ext == ".kt" || ext == ".xml" {
			c.analyzeHardcodedValues(path)
		}
		
		return nil
	})
}

func (c *CodeQualityChecker) analyzeHardcodedValues(filePath string) {
	file, err := os.Open(filePath)
	if err != nil {
		return
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	lineNum := 0
	
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		
		// Skip comments and empty lines
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "<!--") {
			continue
		}
		
		// Critical hardcoded values
		criticalPatterns := []struct {
			pattern     *regexp.Regexp
			description string
		}{
			{regexp.MustCompile(`(?i)"[a-zA-Z0-9]{20,}"`), "Potential hardcoded API key or token"},
			{regexp.MustCompile(`(?i)password\s*=\s*"[^"]+"`), "Hardcoded password"},
			{regexp.MustCompile(`(?i)secret\s*=\s*"[^"]+"`), "Hardcoded secret"},
			{regexp.MustCompile(`(?i)token\s*=\s*"[^"]+"`), "Hardcoded token"},
			{regexp.MustCompile(`(?i)api_?key\s*=\s*"[^"]+"`), "Hardcoded API key"},
		}
		
		for _, cp := range criticalPatterns {
			if cp.pattern.MatchString(line) {
				c.addIssue(filePath, lineNum, "Hardcoded Secret", cp.description, "CRITICAL")
			}
		}
		
		// High priority hardcoded values
		highPatterns := []struct {
			pattern     *regexp.Regexp
			description string
		}{
			{regexp.MustCompile(`"https?://[^"]+"`), "Hardcoded URL - should be configurable"},
			{regexp.MustCompile(`(?i)database.*=.*"[^"]+"`), "Hardcoded database configuration"},
			{regexp.MustCompile(`(?i)server.*=.*"[^"]+"`), "Hardcoded server configuration"},
		}
		
		for _, hp := range highPatterns {
			if hp.pattern.MatchString(line) {
				c.addIssue(filePath, lineNum, "Hardcoded Config", hp.description, "HIGH")
			}
		}
		
		// Medium priority hardcoded values
		mediumPatterns := []struct {
			pattern     *regexp.Regexp
			description string
		}{
			{regexp.MustCompile(`"[^"]*@[^"]*\.[^"]*"`), "Hardcoded email address"},
			{regexp.MustCompile(`"\+?[0-9\-\s\(\)]{10,}"`), "Hardcoded phone number"},
			{regexp.MustCompile(`"[0-9]{4,}"`), "Potential hardcoded numeric value"},
		}
		
		for _, mp := range mediumPatterns {
			if mp.pattern.MatchString(line) {
				c.addIssue(filePath, lineNum, "Hardcoded Value", mp.description, "MEDIUM")
			}
		}
	}
}