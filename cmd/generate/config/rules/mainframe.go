package rules

import (
	"github.com/betterleaks/betterleaks/v2/cmd/generate/config/utils"
	"github.com/betterleaks/betterleaks/v2/config"
)

// RACF passwords are one to eight characters from A-Z, 0-9, @, # and $, and a real one is often a
// word with a digit, so these filters drop known placeholders rather than low entropy.
const racfPlaceholder = `(?i)^(?:x+|\*+|y+|n+|pass|passw(?:or)?d?|pwd|secret|dummy|changeme|password|newpass(?:word)?|oldpass(?:word)?)$`

func MainframeJCLPassword() *config.Rule {
	r := config.Rule{
		ID:          "jcl-racf-password",
		Description: "Identified a RACF password in a JCL statement, exposing the z/OS user ID it signs on.",
		Confidence:  "medium",
		Regex:       `(?im)^//[^*\n][^\n]*?\bPASSWORD=\(?([A-Z0-9@#$]{1,8})(?:[,)'\s]|$)`,
		ValueGroup:  1,
		Keywords:    []string{"password="},
		FilterExpr:  "matchesAny(finding[\"secret\"], [`" + racfPlaceholder + "`])",
	}

	tps := []string{
		`//PAYROLL  JOB (ACCT),'RUN',CLASS=A,MSGCLASS=X,USER=PAYADM,PASSWORD=K7QX2MPL`,
		`//NIGHTLY  JOB (ACCT),USER=BATCH01,PASSWORD=(Q9W8E7R6,Z1X2C3V4)`,
		`//STEP1    EXEC PGM=FTPXFER,PARM='USER=OPS,PASSWORD=M4INFR4M'`,
		`//payroll  job (acct),user=payadm,password=k7qx2mpl`,
	}
	fps := []string{
		`//PAYROLL  JOB (ACCT),'RUN',CLASS=A,USER=&SYSUID,PASSWORD=&PW`, // symbolic parameter
		`//STEP0    JOB (ACCT),'RUN',PASSWORD=XXXXXXXX`,                 // placeholder
		`//* PASSWORD=K7QX2MPL mentioned in a comment line`,             // JCL comment
		`PASSWORD=K7QX2MPL`, // not a JCL statement
		`//STEP2    EXEC PGM=IEBGENER,PARM='PASSWORD=PASSWORD'`, // placeholder
	}
	return utils.Validate(r, tps, fps)
}

func MainframeCOBOLValueCredential() *config.Rule {
	r := config.Rule{
		ID:          "cobol-value-credential",
		Description: "Identified a COBOL data item named for a credential with a literal VALUE, embedding the credential in the program.",
		Confidence:  "medium",
		// Levels 01-49 and 77 hold data; a level-88 condition name does not. TOKEN alone in a
		// COBOL name is usually a parser or SQL token, so only credential tokens count.
		Regex:    `(?im)^[^*\n]{0,7}\s*\b(?:0?[1-9]|[1-4][0-9]|77)\s+[A-Z0-9-]*(?:PASSWORD|PASSWD|PASSWRD|PSWD|PWD|SECRET|APIKEY|API-KEY|ACCESS-KEY|(?:API|ACCESS|AUTH|BEARER|OAUTH|REFRESH)-?TOKEN)[A-Z0-9-]*\b[^\n.]*?\bVALUES?\s+(?:IS\s+|ARE\s+)?(?:'([^'\n]{1,})'|"([^"\n]{1,})")`,
		Path:     `(?i)\.(?:cbl|cob|cobol|cpy|copy|sqb|pco|ccp)$`,
		Keywords: []string{"password", "passwd", "passwrd", "pswd", "pwd", "secret", "apikey", "api-key", "access-key", "token"},
		FilterExpr: "matchesAny(finding[\"secret\"], [`" +
			`(?i)^(?:x+|\*+|\s+|y|n|yes|no|true|false|on|off|[01]|pass(?:word)?|secret|dummy|changeme|password:?|enter.*|invalid.*|wrong.*)$` +
			"`])",
	}

	tps := map[string]string{
		"login.cbl":   `       01 WS-DB-PASSWORD      PIC X(16) VALUE 'Tr0ub4dor3xQz9'.`,
		"api.cob":     `       01 WS-API-TOKEN        PIC X(20) VALUE "ghx8Kq2LmPz7Rt4Vw9Ys".`,
		"FTPPARM.CPY": `           05  FTP-PASSWD     PIC X(08) VALUE IS 'M4INFR4M'.`,
		"auth.cpy":    `           05  WS-AUTH-TOKEN  PIC X(20) VALUE 'q8Lm2Zp7Rt4Vw9YsKx3N'.`,
	}
	fps := map[string]string{
		"a.cbl":     `       01 WS-DB-PASSWORD      PIC X(16) VALUE SPACES.`,            // figurative constant
		"b.cbl":     `       01 WS-PASSWORD-PROMPT  PIC X(20) VALUE 'Enter password:'.`, // prompt text
		"c.cbl":     `       01 WS-PASSWORD-MASK    PIC X(8)  VALUE '********'.`,        // mask
		"d.cbl":     `      *01 WS-OLD-PASSWORD     PIC X(16) VALUE 'Tr0ub4dor3xQz9'.`,  // comment line
		"login.txt": `       01 WS-DB-PASSWORD      PIC X(16) VALUE 'Tr0ub4dor3xQz9'.`,  // not COBOL source
		"e.cbl":     `       01 WS-CUSTOMER-NAME    PIC X(16) VALUE 'Tr0ub4dor3xQz9'.`,  // not a credential name
		"f.cbl":     `           88 PASSWORD-OK               VALUE 'Y'.`,               // condition name
		"g.cbl":     `              88 TOKEN-IS-CICS-RESERVED VALUE 'ABCODE'.`,          // condition name
		"h.cbl":     `     88 TOKEN-KEY VALUE '1'.`,                                     // free-format condition name
		"i.cbl":     `       01 WS-PASSWORD-STATE   PIC X     VALUE 'N'.`,               // flag value
		"j.cbl":     `           05 WS-TOKEN        PIC X(30) VALUE 'UNKNOWN'.`,         // parser token
		"k.cbl":     `       77 SQL-SYNTAX-TOKEN-MISSING PIC X(5) VALUE '37501'.`,       // SQLSTATE
	}
	return utils.ValidateWithPaths(r, tps, fps)
}

func MainframeEmbeddedSQLConnectPassword() *config.Rule {
	r := config.Rule{
		ID:          "embedded-sql-connect-password",
		Description: "Identified an embedded SQL CONNECT with a literal password, exposing the database user it signs on.",
		Confidence:  "medium",
		Regex:       `(?is)\bCONNECT\s+(?:TO\s+\S+\s+)?(?:USER\s+(?:'[^']*'|"[^"]*"|:?[A-Z0-9-]+)\s+USING|(?:(?:'[^']*'|"[^"]*"|:?[A-Z0-9-]+)\s+)?IDENTIFIED\s+BY)\s+(?:'([^'\n]{3,})'|"([^"\n]{3,})")`,
		Keywords:    []string{"connect"},
		FilterExpr: "matchesAny(finding[\"secret\"], [`" +
			`(?i)^(?:x+|\*+|pass(?:word)?|pwd|secret|dummy|changeme|your[-_ ]?password|<[^>]*>)$` +
			"`])",
	}

	tps := []string{
		`           EXEC SQL CONNECT TO SAMPLE USER 'DB2ADM' USING 'Pa55w0rdZ9q' END-EXEC.`,
		`           EXEC SQL CONNECT TO :DBNAME USER :WS-USER USING 'Pa55w0rdZ9q' END-EXEC.`,
		`           EXEC SQL CONNECT 'SCOTT' IDENTIFIED BY 'T1ger7Q2' END-EXEC.`,
		`           EXEC SQL CONNECT :USERNAME IDENTIFIED BY "T1ger7Q2" END-EXEC.`,
	}
	fps := []string{
		`           EXEC SQL CONNECT TO SAMPLE USER :WS-USER USING :WS-DB-PASSWORD END-EXEC.`, // host variables
		`           EXEC SQL CONNECT TO 'database' USER 'user' USING 'password' END-EXEC.`,    // placeholder
		`           EXEC SQL CONNECT :USERNAME IDENTIFIED BY :PASSWD END-EXEC.`,               // host variable
		`           EXEC SQL CONNECT TO SAMPLE END-EXEC.`,                                     // no credentials
	}
	return utils.Validate(r, tps, fps)
}
