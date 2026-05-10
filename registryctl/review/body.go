package review

import (
	"fmt"
	"regexp"
	"strings"
)

var abuseAgreementPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?im)^\s*-\s*\[[xX]\]\s*.*phishing.*malware.*spam.*abuse.*illegal services`),
	regexp.MustCompile(`(?im)^\s*-\s*\[[xX]\]\s*.*impersonate others.*misleading services`),
	regexp.MustCompile(`(?im)^\s*-\s*\[[xX]\]\s*.*resell.*transfer.*commercial product`),
	regexp.MustCompile(`(?im)^\s*-\s*\[[xX]\]\s*.*maintainers may reject or remove records`),
}

func CheckAbuseAgreement(body string) error {
	body = strings.TrimSpace(body)
	if body == "" {
		return fmt.Errorf("PR body is empty; please complete the abuse prevention agreement")
	}

	for index, pattern := range abuseAgreementPatterns {
		if !pattern.MatchString(body) {
			return fmt.Errorf("abuse prevention agreement checkbox %d is not checked", index+1)
		}
	}
	return nil
}
