
using ACT.Api;
using ACT.Contracts;
using ACT.DependencyAnalysis;
using ACT.Evidence;
using ACT.SourceAnalysis;
using ACT.Tls.Checks;
using ACT.Web.Checks;

namespace ACT.Cli;

/// <summary>
/// The explicit built-in check registry. Nothing is discovered reflectively at runtime:
/// every executable check is listed here by construction.
/// </summary>
public static class CheckRegistry
{
    public interface IBuiltInCheck : ISecurityCheck
    {
        string Id { get; }
        CheckCategory Category { get; }
        SafetyLevel Safety { get; }
    }

    private sealed class Adapter(ISecurityCheck inner) : IBuiltInCheck
    {
        public string Id => inner.Metadata.Id.Value;
        public CheckCategory Category => inner.Metadata.Category;
        public SafetyLevel Safety => inner.Metadata.SafetyLevel;
        public SecurityCheckMetadata Metadata => inner.Metadata;
        public Task<SecurityCheckResult> ExecuteAsync(SecurityCheckContext context, CancellationToken cancellationToken) =>
            inner.ExecuteAsync(context, cancellationToken);
    }

    /// <summary>The targeted battery plus whether the conventional OpenAPI document answered.</summary>
    public sealed record TargetedCheckSet(IReadOnlyList<ISecurityCheck> Checks, bool OpenApiDocumentPublished);

    /// <summary>Network/web-facing checks bound to a specific base URL.</summary>
    public static IReadOnlyList<ISecurityCheck> CreateTargetedChecks(Uri baseUrl) =>
        CreateTargetedCheckSet(baseUrl).Checks;

    /// <summary>
    /// Assembles the URL-addressable battery and reports honestly whether the OpenAPI surface
    /// analysis was composed at all, so its absence can become a recorded planning decision
    /// instead of an unexplained gap in coverage. When TLS probe services are supplied and the
    /// origin speaks https, the ACT.Tls handshake-inspection battery joins the composition; on
    /// http origins the trio is still handed to the orchestrator so its PROTOCOL_MISMATCH
    /// exclusion becomes a persisted fact rather than a silent omission.
    /// </summary>
    public static TargetedCheckSet CreateTargetedCheckSet(Uri baseUrl, TlsServices? tls = null)
    {
        var list = new List<ISecurityCheck>();
        list.AddRange(BuildWebChecks());

        if (tls is not null)
        {
            list.Add(new CertificateTrustCheck(tls));
            list.Add(new ProtocolVersionsCheck(tls));
            list.Add(new CipherSuiteCheck(tls));
        }

        var openApiUrl = new Uri(baseUrl, "/api/openapi.json");
        using var probe = new System.Net.Http.HttpClient { Timeout = TimeSpan.FromSeconds(10) };
        string? document = null;
        try
        {
            document = probe.GetStringAsync(openApiUrl).GetAwaiter().GetResult();
        }
        catch (Exception)
        {
            // No OpenAPI document published at the conventional location: surface check skips.
        }
        if (document is not null)
        {
            list.Add(new ApiSurfaceAnalysisCheck(() => document, baseUrl));
        }
        return new TargetedCheckSet(list, document is not null);
    }

    /// <summary>
    /// Identifiers of the URL-addressable web checks, so a launch that could not compose them
    /// can record WHY through the planning-exclusion ledger instead of leaving a silent gap.
    /// </summary>
    public static IReadOnlyList<string> WebCheckIds { get; } =
        [.. BuildWebChecks().Select(c => c.Metadata.Id.Value)];

    /// <summary>Identifiers of the network-free repository checks, same purpose as WebCheckIds.</summary>
    public static IReadOnlyList<string> RepositoryCheckIds { get; } =
        [.. CreateRepositoryChecks(
            new EvidenceFactory(new StandardEvidenceRedactor(RedactionPolicy.Standard)))
            .Select(c => c.Metadata.Id.Value)];

    /// <summary>Catalog listing used by 'artemis check list' and by every coverage surface's
    /// never-executed comparison; the TLS inspection checks appear through their static
    /// metadata because their construction needs probe services no catalog read should build.</summary>
    public static IReadOnlyList<SecurityCheckMetadata> Catalog()
    {
        var metadata = new List<SecurityCheckMetadata>();
        metadata.AddRange(BuildWebChecks().Select(c => c.Metadata));
        metadata.Add(CertificateTrustCheck.Describe());
        metadata.Add(ProtocolVersionsCheck.Describe());
        metadata.Add(CipherSuiteCheck.Describe());
        var evidence = new EvidenceFactory(new StandardEvidenceRedactor(RedactionPolicy.Standard));
        metadata.Add(new SourceAnalysisCheck(evidence).Metadata);
        metadata.Add(new DependencyAnalysisCheck(DisabledAdvisoryProvider.Instance, evidence).Metadata);
        return metadata;
    }

    /// <summary>
    /// Network-free checks bound to a local repository asset: source-rule scanning over the
    /// walked tree and manifest-based dependency auditing. With no feed configured (the
    /// shipping default) the dependency audit runs against the honest disabled provider, so
    /// results are reported as inconclusive rather than as a clean bill of health.
    /// </summary>
    public static IReadOnlyList<ISecurityCheck> CreateRepositoryChecks(IEvidenceFactory evidence) =>
    [
        new SourceAnalysisCheck(evidence),
        new DependencyAnalysisCheck(DisabledAdvisoryProvider.Instance, evidence)
    ];

    private static List<ISecurityCheck> BuildWebChecks() =>
    [
        new HstsCheck(),
        new CspCheck(),
        new SecurityHeadersCheck(),
        new CookieFlagCheck(),
        new CorsCheck(),
        new TlsRedirectCheck(),
        new MixedContentCheck(),
        new InfoDisclosureCheck(),
        new CacheControlCheck()
    ];
}
