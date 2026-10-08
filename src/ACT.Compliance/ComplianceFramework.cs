namespace ACT.Compliance;

public enum ComplianceFramework
{
    None,
    SOC2,
    HIPAA,
    PCI_DSS,
    ISO_27001,
    NIST_CSF,
    GDPR
}

public record ComplianceMapping(
    string CheckId,
    ComplianceFramework Framework,
    string ControlId,
    string ControlName,
    string ControlDescription);

public static class ComplianceMappingRegistry
{
    private static readonly IReadOnlyList<ComplianceMapping> Mappings = new List<ComplianceMapping>
    {
        // SOC2 mappings
        new("ACT-WEB-HSTS-001", ComplianceFramework.SOC2, "CC6.1", "Logical Access Security", "HSTS header enforces HTTPS connections"),
        new("ACT-WEB-CSP-001", ComplianceFramework.SOC2, "CC6.1", "Logical Access Security", "Content Security Policy restricts resource loading"),
        new("ACT-WEB-CORS-001", ComplianceFramework.SOC2, "CC6.1", "Logical Access Security", "CORS configuration restricts cross-origin access"),
        new("ACT-WEB-COOKIE-001", ComplianceFramework.SOC2, "CC6.1", "Logical Access Security", "Cookie flags protect session data"),
        new("ACT-TLS-CERT-001", ComplianceFramework.SOC2, "CC6.3", "Encryption", "TLS certificate is valid and trusted"),
        new("ACT-TLS-CIPHER-001", ComplianceFramework.SOC2, "CC6.3", "Encryption", "Strong cipher suites are used"),
        new("ACT-TLS-PROTO-001", ComplianceFramework.SOC2, "CC6.3", "Encryption", "Modern TLS protocol versions are supported"),
        new("ACT-WEB-XSS-001", ComplianceFramework.SOC2, "CC6.1", "Logical Access Security", "Cross-site scripting vulnerabilities are detected"),
        new("ACT-WEB-SQLI-001", ComplianceFramework.SOC2, "CC6.1", "Logical Access Security", "SQL injection vulnerabilities are detected"),

        // HIPAA mappings
        new("ACT-WEB-HSTS-001", ComplianceFramework.HIPAA, "164.312(e)(1)", "Transmission Security", "HSTS header enforces HTTPS connections"),
        new("ACT-TLS-CERT-001", ComplianceFramework.HIPAA, "164.312(e)(1)", "Transmission Security", "TLS certificate is valid and trusted"),
        new("ACT-TLS-CIPHER-001", ComplianceFramework.HIPAA, "164.312(e)(2)", "Encryption", "Strong cipher suites are used"),
        new("ACT-WEB-COOKIE-001", ComplianceFramework.HIPAA, "164.312(a)(1)", "Access Control", "Cookie flags protect session data"),
        new("ACT-WEB-XSS-001", ComplianceFramework.HIPAA, "164.312(a)(1)", "Access Control", "Cross-site scripting vulnerabilities are detected"),
        new("ACT-WEB-SQLI-001", ComplianceFramework.HIPAA, "164.312(a)(1)", "Access Control", "SQL injection vulnerabilities are detected"),
        new("ACT-WEB-INFODISCLOSURE-001", ComplianceFramework.HIPAA, "164.312(a)(2)", "Access Control", "Information disclosure is detected"),

        // PCI DSS mappings
        new("ACT-WEB-HSTS-001", ComplianceFramework.PCI_DSS, "4.1", "Encrypt Transmission", "HSTS header enforces HTTPS connections"),
        new("ACT-TLS-CERT-001", ComplianceFramework.PCI_DSS, "4.1", "Encrypt Transmission", "TLS certificate is valid and trusted"),
        new("ACT-TLS-CIPHER-001", ComplianceFramework.PCI_DSS, "4.1", "Encrypt Transmission", "Strong cipher suites are used"),
        new("ACT-TLS-PROTO-001", ComplianceFramework.PCI_DSS, "4.1", "Encrypt Transmission", "Modern TLS protocol versions are supported"),
        new("ACT-WEB-COOKIE-001", ComplianceFramework.PCI_DSS, "6.5", "Secure Coding", "Cookie flags protect session data"),
        new("ACT-WEB-XSS-001", ComplianceFramework.PCI_DSS, "6.5", "Secure Coding", "Cross-site scripting vulnerabilities are detected"),
        new("ACT-WEB-SQLI-001", ComplianceFramework.PCI_DSS, "6.5", "Secure Coding", "SQL injection vulnerabilities are detected"),
        new("ACT-WEB-CSRF-001", ComplianceFramework.PCI_DSS, "6.5", "Secure Coding", "CSRF vulnerabilities are detected"),

        // ISO 27001 mappings
        new("ACT-WEB-HSTS-001", ComplianceFramework.ISO_27001, "A.13.1.1", "Network Security Management", "HSTS header enforces HTTPS connections"),
        new("ACT-TLS-CERT-001", ComplianceFramework.ISO_27001, "A.13.2.1", "Cryptographic Controls", "TLS certificate is valid and trusted"),
        new("ACT-TLS-CIPHER-001", ComplianceFramework.ISO_27001, "A.13.2.1", "Cryptographic Controls", "Strong cipher suites are used"),
        new("ACT-WEB-COOKIE-001", ComplianceFramework.ISO_27001, "A.9.2.3", "Access Control", "Cookie flags protect session data"),
        new("ACT-WEB-XSS-001", ComplianceFramework.ISO_27001, "A.14.2.5", "Secure Development", "Cross-site scripting vulnerabilities are detected"),
        new("ACT-WEB-SQLI-001", ComplianceFramework.ISO_27001, "A.14.2.5", "Secure Development", "SQL injection vulnerabilities are detected"),

        // NIST CSF mappings
        new("ACT-WEB-HSTS-001", ComplianceFramework.NIST_CSF, "PR.DS-4", "Data-at-rest Protection", "HSTS header enforces HTTPS connections"),
        new("ACT-TLS-CERT-001", ComplianceFramework.NIST_CSF, "PR.DS-4", "Data-at-rest Protection", "TLS certificate is valid and trusted"),
        new("ACT-TLS-CIPHER-001", ComplianceFramework.NIST_CSF, "PR.DS-4", "Data-at-rest Protection", "Strong cipher suites are used"),
        new("ACT-WEB-XSS-001", ComplianceFramework.NIST_CSF, "PR.IP-12", "Security Engineering", "Cross-site scripting vulnerabilities are detected"),
        new("ACT-WEB-SQLI-001", ComplianceFramework.NIST_CSF, "PR.IP-12", "Security Engineering", "SQL injection vulnerabilities are detected"),

        // GDPR mappings
        new("ACT-WEB-HSTS-001", ComplianceFramework.GDPR, "Art. 32", "Security of Processing", "HSTS header enforces HTTPS connections"),
        new("ACT-TLS-CERT-001", ComplianceFramework.GDPR, "Art. 32", "Security of Processing", "TLS certificate is valid and trusted"),
        new("ACT-TLS-CIPHER-001", ComplianceFramework.GDPR, "Art. 32", "Security of Processing", "Strong cipher suites are used"),
        new("ACT-WEB-COOKIE-001", ComplianceFramework.GDPR, "Art. 32", "Security of Processing", "Cookie flags protect session data"),
        new("ACT-WEB-XSS-001", ComplianceFramework.GDPR, "Art. 32", "Security of Processing", "Cross-site scripting vulnerabilities are detected"),
        new("ACT-WEB-SQLI-001", ComplianceFramework.GDPR, "Art. 32", "Security of Processing", "SQL injection vulnerabilities are detected"),
    };

    public static IReadOnlyList<ComplianceMapping> GetMappingsForCheck(string checkId)
    {
        return Mappings.Where(m => m.CheckId == checkId).ToArray();
    }

    public static IReadOnlyList<ComplianceMapping> GetMappingsForFramework(ComplianceFramework framework)
    {
        return Mappings.Where(m => m.Framework == framework).ToArray();
    }

    public static IReadOnlyList<ComplianceFramework> GetFrameworksForCheck(string checkId)
    {
        return Mappings.Where(m => m.CheckId == checkId).Select(m => m.Framework).Distinct().ToArray();
    }
}
