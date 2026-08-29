using ACT.Contracts;

namespace ACT.Remediation;

/// <summary>
/// Deterministically derives an executable remediation plan from a finding's check id and class.
/// Only finding classes with a safe, machine-applicable fix get a plan; everything else is
/// honestly reported as not remediable rather than pretending a fix exists.
/// </summary>
public static class RemediationPlanner
{
    // Recommended secure header values applied by the remediation proxy.
    public const string HstsValue = "max-age=31536000; includeSubDomains; preload";
    public const string CspValue = "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'";
    public const string NosniffValue = "nosniff";
    public const string ReferrerPolicyValue = "strict-origin-when-cross-origin";
    public const string PermissionsPolicyValue = "geolocation=(), microphone=(), camera=(), payment=()";
    public const string CacheControlValue = "no-store";

    /// <summary>
    /// Builds the remediation plan for a finding, or null when no executable fix exists for its
    /// class. The finding class is recovered from the fingerprint's deterministic components.
    /// </summary>
    public static RemediationPlan? PlanFor(Finding finding, string? findingClass = null)
    {
        var checkId = finding.CheckId.Value;
        var cls = findingClass ?? InferFindingClass(finding);

        RemediationAction[]? actions = (checkId, cls) switch
        {
            // HSTS: missing / malformed / too short -> emit a compliant header.
            ("ACT-WEB-HSTS-001", _) =>
            [
                new RemediationAction(RemediationActionKind.InjectHeader, "Strict-Transport-Security", HstsValue,
                    "Inject a compliant Strict-Transport-Security header (1y, includeSubDomains).")
            ],

            // CSP: missing / unsafe inline -> emit a restrictive policy.
            ("ACT-WEB-CSP-001", _) =>
            [
                new RemediationAction(RemediationActionKind.InjectHeader, "Content-Security-Policy", CspValue,
                    "Inject a restrictive Content-Security-Policy defaulting to same-origin sources.")
            ],

            // Baseline security headers -> emit the full recommended set.
            ("ACT-WEB-SECHEADERS-002", _) =>
            [
                new RemediationAction(RemediationActionKind.InjectHeader, "X-Content-Type-Options", NosniffValue,
                    "Inject X-Content-Type-Options: nosniff."),
                new RemediationAction(RemediationActionKind.InjectHeader, "Referrer-Policy", ReferrerPolicyValue,
                    "Inject a strict Referrer-Policy."),
                new RemediationAction(RemediationActionKind.InjectHeader, "Permissions-Policy", PermissionsPolicyValue,
                    "Inject a Permissions-Policy disabling unused powerful features.")
            ],

            // CORS wildcard / reflection -> strip the permissive grant.
            ("ACT-WEB-CORS-001", _) =>
            [
                new RemediationAction(RemediationActionKind.RemoveHeader, "Access-Control-Allow-Origin", null,
                    "Remove the wildcard/reflective Access-Control-Allow-Origin grant."),
                new RemediationAction(RemediationActionKind.RemoveHeader, "Access-Control-Allow-Credentials", null,
                    "Remove Access-Control-Allow-Credentials paired with a permissive origin.")
            ],

            // Cache control -> forbid caching of sensitive responses.
            ("ACT-WEB-CACHECTRL-001", _) =>
            [
                new RemediationAction(RemediationActionKind.InjectHeader, "Cache-Control", CacheControlValue,
                    "Inject Cache-Control: no-store to prevent sensitive responses from being cached.")
            ],

            // Cookies: harden every Set-Cookie with the missing attributes.
            ("ACT-WEB-COOKIE-001", _) =>
            [
                new RemediationAction(RemediationActionKind.HardenSetCookie, null, "Secure; HttpOnly; SameSite=Strict",
                    "Rewrite Set-Cookie headers to add Secure, HttpOnly, and SameSite=Strict.")
            ],

            // TLS redirect: force HTTP -> HTTPS upgrade at the remediation edge.
            ("ACT-WEB-TLSREDIRECT-001", _) =>
            [
                new RemediationAction(RemediationActionKind.ForceHttpsRedirect, null, null,
                    "Redirect plain-HTTP requests to their HTTPS equivalent.")
            ],

            _ => null
        };

        if (actions is null || actions.Length == 0)
        {
            return null;
        }

        return new RemediationPlan(
            finding.FindingId,
            finding.CheckId,
            cls,
            finding.Title,
            actions,
            "Apply " + actions.Length + " corrective action(s) at the remediation edge for " + finding.Title + ".");
    }

    /// <summary>
    /// Recovers the finding class token from the finding's title/class heuristics. Checks embed a
    /// stable class string in the fingerprint; when the caller cannot supply it we derive a best
    /// effort from the title so planning stays deterministic per finding.
    /// </summary>
    private static string InferFindingClass(Finding finding) =>
        finding.Title.Trim().ToLowerInvariant()
            .Replace(" ", "_")
            .Replace("-", "_");
}
