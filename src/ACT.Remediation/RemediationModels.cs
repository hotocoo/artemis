using ACT.Contracts;

namespace ACT.Remediation;

/// <summary>
/// The kind of concrete, machine-applicable fix a remediation action performs. Actions are the
/// unit of "fixing on the spot": each one is deterministic, describable, and verifiable by
/// re-running the originating check.
/// </summary>
public enum RemediationActionKind
{
    /// <summary>Add or replace a response header with a fixed value.</summary>
    InjectHeader,

    /// <summary>Remove a response header entirely (e.g. a wildcard CORS grant).</summary>
    RemoveHeader,

    /// <summary>Rewrite every Set-Cookie header to include the given security attributes.</summary>
    HardenSetCookie,

    /// <summary>Redirect plain-HTTP requests to the HTTPS equivalent origin.</summary>
    ForceHttpsRedirect
}

/// <summary>
/// One concrete fix step. The planner emits these; the remediation proxy executes them against
/// live responses so the vulnerable target is corrected in place (from the client's viewpoint).
/// </summary>
public sealed record RemediationAction(
    RemediationActionKind Kind,
    string? HeaderName,
    string? HeaderValue,
    string Description);

/// <summary>
/// The complete remediation plan for one finding: the ordered actions that correct it plus a
/// human-readable summary. Plans are deterministic functions of the finding class.
/// </summary>
public sealed record RemediationPlan(
    Guid FindingId,
    CheckId CheckId,
    string FindingClass,
    string Title,
    IReadOnlyList<RemediationAction> Actions,
    string Summary);

/// <summary>Whether a remediation attempt corrected and verified the finding.</summary>
public enum RemediationOutcome
{
    /// <summary>The fix was applied and the re-check confirmed the finding is resolved.</summary>
    Remediated,

    /// <summary>The fix was applied but the re-check still reports the finding.</summary>
    AppliedNotVerified,

    /// <summary>No executable remediation exists for this finding class.</summary>
    NotRemediable,

    /// <summary>Remediation could not be applied safely.</summary>
    Failed
}

/// <summary>
/// The result of one remediation attempt: what was done, where the corrected endpoint is, and
/// whether verification confirmed the fix.
/// </summary>
public sealed record RemediationResult(
    Guid FindingId,
    RemediationOutcome Outcome,
    string? RemediatedEndpoint,
    string Detail,
    DateTimeOffset AppliedUtc, DateTimeOffset VerifiedUtc,
    int FindingsBefore,
    int FindingsAfter);
