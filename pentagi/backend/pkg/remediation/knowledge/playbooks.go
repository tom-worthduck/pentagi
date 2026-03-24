// Package knowledge contains deterministic remediation playbooks.
package knowledge

import (
	"strings"

	"pentagi/pkg/remediation/models"
)

// Playbook is a deterministic remediation mapping.
type Playbook struct {
	MatchTitleContains []string
	MatchTagsContains  []string
	Category           models.Category
	Title              string
	Rationale          string
	Actions            []string
	Prechecks          []string
	Verification       []string
	Rollback           []string
	Impact             models.Impact
}

// DefaultPlaybooks covers the MVP finding classes from the PRD.
var DefaultPlaybooks = []Playbook{
	// 1. SQL Injection
	{
		MatchTitleContains: []string{"sql injection"},
		MatchTagsContains:  []string{"sqli"},
		Category:           models.CategoryApplication,
		Title:              "Remediate SQL injection vulnerability",
		Rationale:          "SQL injection enables data theft, authentication bypass, and remote code execution.",
		Actions: []string{
			"Replace string-concatenated SQL queries with parameterized queries or prepared statements.",
			"Deploy a web application firewall (WAF) rule to block common SQLi payloads.",
			"Review all database-facing code paths for injection points.",
		},
		Prechecks: []string{
			"Identify all code paths that construct SQL from user input.",
			"Confirm a staging environment is available for testing the fix.",
		},
		Verification: []string{
			"Re-run the original SQLi test (e.g. sqlmap) against the patched application.",
			"Confirm parameterized queries are used in the patched code.",
		},
		Rollback: []string{
			"Revert to the previous application version if the fix causes regressions.",
			"Disable the WAF rule if it blocks legitimate traffic.",
		},
		Impact: models.ImpactHigh,
	},
	// 2. Cross-Site Scripting (XSS)
	{
		MatchTitleContains: []string{"cross-site scripting", "xss"},
		MatchTagsContains:  []string{"xss"},
		Category:           models.CategoryApplication,
		Title:              "Remediate cross-site scripting vulnerability",
		Rationale:          "XSS allows session hijacking, credential theft, and defacement.",
		Actions: []string{
			"Apply context-aware output encoding to all user-controlled values.",
			"Implement Content-Security-Policy headers to restrict inline script execution.",
			"Review and sanitize all input rendering paths.",
		},
		Prechecks: []string{
			"Identify all locations where user input is rendered in HTML, JavaScript, or CSS contexts.",
		},
		Verification: []string{
			"Re-test with the original XSS payloads to confirm they are neutralized.",
			"Verify CSP headers are present in HTTP responses.",
		},
		Rollback: []string{
			"Revert encoding changes if they break legitimate application functionality.",
		},
		Impact: models.ImpactMedium,
	},
	// 3. Cross-Site Request Forgery (CSRF)
	{
		MatchTitleContains: []string{"cross-site request forgery", "csrf"},
		MatchTagsContains:  []string{"csrf"},
		Category:           models.CategoryApplication,
		Title:              "Add CSRF protection to state-changing operations",
		Rationale:          "Lack of CSRF protection allows attackers to perform actions on behalf of authenticated users.",
		Actions: []string{
			"Generate and validate anti-CSRF tokens on all state-changing forms and endpoints.",
			"Set SameSite=Strict or SameSite=Lax on session cookies.",
			"Validate the Origin/Referer header on state-changing requests.",
		},
		Prechecks: []string{
			"Identify all state-changing endpoints (POST, PUT, DELETE).",
			"Confirm session management supports CSRF token storage.",
		},
		Verification: []string{
			"Confirm CSRF tokens are required and validated on all state-changing requests.",
			"Verify that requests without valid tokens are rejected.",
		},
		Rollback: []string{
			"Remove token validation if it breaks legitimate cross-origin integrations.",
		},
		Impact: models.ImpactLow,
	},
	// 4. Command Injection / RCE
	{
		MatchTitleContains: []string{"command injection", "rce", "remote code execution"},
		MatchTagsContains:  []string{"rce", "command-injection"},
		Category:           models.CategoryApplication,
		Title:              "Remediate command injection / remote code execution",
		Rationale:          "Command injection allows full system compromise and lateral movement.",
		Actions: []string{
			"Replace shell command construction with safe APIs that do not invoke a shell.",
			"Apply strict input validation and allowlisting for any required command arguments.",
			"Run the application with least-privilege OS permissions.",
		},
		Prechecks: []string{
			"Identify code paths that pass user input to OS commands or shell interpreters.",
		},
		Verification: []string{
			"Re-test with the original injection payloads to confirm they are blocked.",
			"Verify the application process runs under a restricted user account.",
		},
		Rollback: []string{
			"Revert to the prior code version if the fix breaks required functionality.",
		},
		Impact: models.ImpactHigh,
	},
	// 5. Exposed Remote Desktop (RDP)
	{
		MatchTitleContains: []string{"rdp", "remote desktop", "exposed remote desktop", "3389"},
		MatchTagsContains:  []string{"rdp"},
		Category:           models.CategoryNetwork,
		Title:              "Restrict exposed RDP access",
		Rationale:          "Externally exposed RDP increases attack surface and enables brute-force and credential attacks.",
		Actions: []string{
			"Restrict inbound RDP to approved management networks or VPN-only access.",
			"Enable Network Level Authentication (NLA) and enforce MFA.",
			"Disable direct internet exposure where not operationally required.",
		},
		Prechecks: []string{
			"Identify legitimate administrative workflows that rely on RDP.",
			"Confirm approved management subnets, VPN paths, or bastion hosts.",
		},
		Verification: []string{
			"Confirm RDP is no longer reachable from unauthorized networks.",
			"Confirm authorized administrators can still connect through the approved path.",
		},
		Rollback: []string{
			"Restore prior firewall rule or access policy if approved access is broken.",
		},
		Impact: models.ImpactMedium,
	},
	// 6. Weak or Exposed Credentials
	{
		MatchTitleContains: []string{"weak", "exposed credentials", "default password", "credential"},
		MatchTagsContains:  []string{"credentials", "password"},
		Category:           models.CategoryIdentity,
		Title:              "Rotate and strengthen exposed credentials",
		Rationale:          "Weak or exposed credentials provide direct unauthorized access.",
		Actions: []string{
			"Immediately rotate all compromised or exposed credentials.",
			"Enforce a strong password policy (minimum 12 characters, complexity requirements).",
			"Remove default and hardcoded credentials from application code and configuration.",
			"Enable multi-factor authentication for all privileged accounts.",
		},
		Prechecks: []string{
			"Identify all accounts using the exposed or default credentials.",
			"Confirm credential rotation will not break automated processes without updating them.",
		},
		Verification: []string{
			"Confirm old credentials no longer grant access.",
			"Verify MFA is enforced on privileged accounts.",
		},
		Rollback: []string{
			"Restore prior credentials only if rotation breaks critical business operations (then re-rotate immediately after).",
		},
		Impact: models.ImpactHigh,
	},
	// 7. Excessive Administrative Privileges
	{
		MatchTitleContains: []string{"admin", "privilege", "excessive", "local administrator"},
		MatchTagsContains:  []string{"privilege", "identity"},
		Category:           models.CategoryIdentity,
		Title:              "Reduce excessive administrative access",
		Rationale:          "Over-privileged access increases blast radius after compromise.",
		Actions: []string{
			"Review group memberships and remove unnecessary administrative privileges.",
			"Enforce tiered admin access and separate privileged from daily-use accounts.",
			"Implement just-in-time (JIT) privilege elevation where supported.",
		},
		Prechecks: []string{
			"Identify business owners for privileged accounts and groups.",
			"Confirm which services or tasks depend on current privileges.",
		},
		Verification: []string{
			"Confirm unauthorized accounts no longer retain elevated rights.",
			"Confirm required admin workflows still function.",
		},
		Rollback: []string{
			"Re-add removed permissions only if required to restore critical operations.",
		},
		Impact: models.ImpactHigh,
	},
	// 8. Missing Security Logging
	{
		MatchTitleContains: []string{"logging", "audit", "telemetry", "missing log"},
		MatchTagsContains:  []string{"logging", "detection"},
		Category:           models.CategoryLogging,
		Title:              "Enable missing security logging and telemetry",
		Rationale:          "Insufficient logging reduces detection coverage and weakens incident response.",
		Actions: []string{
			"Enable the applicable security logging baseline for the affected platform.",
			"Enable command/process auditing appropriate to the finding context.",
			"Forward required logs to the approved collection platform.",
		},
		Prechecks: []string{
			"Validate log retention, storage, and forwarding capacity.",
			"Confirm privacy and operational requirements for additional telemetry.",
		},
		Verification: []string{
			"Confirm events are generated locally.",
			"Confirm events arrive at the central logging platform.",
		},
		Rollback: []string{
			"Revert the new logging policy if it creates unacceptable operational impact.",
		},
		Impact: models.ImpactLow,
	},
	// 9. Insecure Configuration
	{
		MatchTitleContains: []string{"insecure config", "misconfiguration", "security header"},
		MatchTagsContains:  []string{"misconfiguration"},
		Category:           models.CategoryApplication,
		Title:              "Fix insecure application or server configuration",
		Rationale:          "Misconfigurations expose unnecessary attack surface and weaken security controls.",
		Actions: []string{
			"Apply the vendor-recommended security hardening baseline.",
			"Enable security headers (HSTS, X-Content-Type-Options, X-Frame-Options, CSP).",
			"Disable unnecessary services, debug endpoints, and default accounts.",
		},
		Prechecks: []string{
			"Review the current configuration against a hardening benchmark (e.g. CIS).",
		},
		Verification: []string{
			"Confirm security headers are present in HTTP responses.",
			"Confirm disabled services are no longer reachable.",
		},
		Rollback: []string{
			"Restore the previous configuration if hardening breaks application functionality.",
		},
		Impact: models.ImpactMedium,
	},
	// 10. Exposed SSH Service
	{
		MatchTitleContains: []string{"ssh", "exposed ssh", "openssh", "22/tcp"},
		MatchTagsContains:  []string{"ssh"},
		Category:           models.CategoryNetwork,
		Title:              "Restrict exposed SSH access",
		Rationale:          "Unrestricted SSH exposure enables brute-force and credential-based attacks.",
		Actions: []string{
			"Restrict inbound SSH to approved management networks or VPN-only access.",
			"Disable password authentication; require key-based auth.",
			"Enforce MFA for SSH where supported.",
		},
		Prechecks: []string{
			"Identify legitimate users and automation that rely on SSH access.",
		},
		Verification: []string{
			"Confirm SSH is no longer reachable from unauthorized networks.",
			"Confirm key-based auth is enforced.",
		},
		Rollback: []string{
			"Restore prior firewall rule if approved access is broken.",
		},
		Impact: models.ImpactMedium,
	},
	// 11. Known CVE / Vulnerable Software Version
	{
		MatchTitleContains: []string{"cve-", "known vulnerability", "vulnerable version", "outdated version"},
		MatchTagsContains:  []string{"cve", "outdated"},
		Category:           models.CategoryPatching,
		Title:              "Patch or mitigate known CVE",
		Rationale:          "Known CVEs have public exploits and are actively targeted by attackers.",
		Actions: []string{
			"Identify the affected software and version from the CVE details.",
			"Apply the vendor-provided patch or upgrade to a fixed version.",
			"If no patch is available, apply the recommended workaround or mitigating controls.",
			"Remove or isolate the affected service if it is not operationally required.",
		},
		Prechecks: []string{
			"Confirm the CVE applies to the running version (not a false positive).",
			"Identify dependencies and services that rely on the affected software.",
			"Verify a tested patch or upgrade path is available.",
		},
		Verification: []string{
			"Confirm the software version has been updated past the vulnerable version.",
			"Re-scan the target to verify the CVE is no longer reported.",
		},
		Rollback: []string{
			"Revert to the prior version if the patch causes regressions.",
			"Re-apply mitigating controls if rollback is required.",
		},
		Impact: models.ImpactHigh,
	},
	// 12. Exposed Web Service / Admin Panel
	{
		MatchTitleContains: []string{"exposed web", "admin panel", "management interface", "grafana", "jenkins", "kibana", "phpmyadmin", "webmin"},
		MatchTagsContains:  []string{"admin-panel", "management-interface", "exposed-web"},
		Category:           models.CategoryNetwork,
		Title:              "Restrict access to exposed web service or admin panel",
		Rationale:          "Exposed management interfaces provide attackers with high-value targets for credential attacks and exploitation.",
		Actions: []string{
			"Restrict access to the management interface to approved networks only (VPN, bastion, or allowlisted IPs).",
			"Enforce authentication and MFA on the management interface.",
			"Update the application to the latest stable version.",
			"Disable the interface entirely if it is not operationally required.",
		},
		Prechecks: []string{
			"Identify who requires access to the management interface and from where.",
			"Confirm the current version and check for known vulnerabilities.",
		},
		Verification: []string{
			"Confirm the interface is no longer reachable from unauthorized networks.",
			"Confirm authorized users can still access it through the approved path.",
		},
		Rollback: []string{
			"Restore prior access rules if the restriction breaks required workflows.",
		},
		Impact: models.ImpactMedium,
	},
	// 13. Outdated or Unpatched Software
	{
		MatchTitleContains: []string{"outdated", "unpatched", "end of life", "eol", "unsupported version", "update available"},
		MatchTagsContains:  []string{"outdated", "eol", "unpatched"},
		Category:           models.CategoryPatching,
		Title:              "Update outdated or unpatched software",
		Rationale:          "Running outdated software increases exposure to known exploits and reduces vendor support for security fixes.",
		Actions: []string{
			"Upgrade the affected software to the latest stable release.",
			"If upgrade is not possible, apply all available security patches.",
			"For end-of-life software, plan migration to a supported alternative.",
		},
		Prechecks: []string{
			"Identify the current version and the latest available version.",
			"Review release notes for breaking changes that may affect operations.",
		},
		Verification: []string{
			"Confirm the software is running the updated version.",
			"Verify that application functionality is preserved after the update.",
		},
		Rollback: []string{
			"Revert to the prior version if the update causes regressions.",
		},
		Impact: models.ImpactMedium,
	},
	// 14. Exposed Database Service
	{
		MatchTitleContains: []string{"exposed database", "mysql exposed", "postgres exposed", "mongodb exposed", "redis exposed", "3306", "5432", "27017", "6379"},
		MatchTagsContains:  []string{"exposed-database"},
		Category:           models.CategoryNetwork,
		Title:              "Restrict access to exposed database service",
		Rationale:          "Externally accessible databases are high-value targets for data theft and ransomware.",
		Actions: []string{
			"Restrict database access to application servers and approved management hosts only.",
			"Ensure the database is not bound to 0.0.0.0 or a public interface.",
			"Enforce strong authentication and disable default accounts.",
			"Enable TLS for database connections.",
		},
		Prechecks: []string{
			"Identify all applications and services that connect to the database.",
			"Confirm firewall rules or network policies can be applied without breaking connectivity.",
		},
		Verification: []string{
			"Confirm the database port is no longer reachable from unauthorized networks.",
			"Confirm application connectivity is preserved.",
		},
		Rollback: []string{
			"Restore prior firewall or bind address configuration if application connectivity is broken.",
		},
		Impact: models.ImpactHigh,
	},
}

// MatchPlaybook returns the first playbook matching the finding, if any.
func MatchPlaybook(f models.NormalizedFinding) (Playbook, bool) {
	title := strings.ToLower(f.Finding.Title)
	tags := strings.ToLower(strings.Join(f.Finding.Tags, " "))

	for _, pb := range DefaultPlaybooks {
		for _, s := range pb.MatchTitleContains {
			if strings.Contains(title, strings.ToLower(s)) {
				return pb, true
			}
		}
		for _, s := range pb.MatchTagsContains {
			if strings.Contains(tags, strings.ToLower(s)) {
				return pb, true
			}
		}
	}
	return Playbook{}, false
}
