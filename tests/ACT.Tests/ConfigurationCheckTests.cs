using ACT.Cli;
using ACT.Cli.Composition;
using ACT.Contracts;
using ACT.DependencyAnalysis;
using ACT.Evidence;
using ACT.Web.Checks;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace ACT.Tests;

/// <summary>
/// Unit coverage for the repository-scoped Configuration checks, the shared repository file
/// scanner, and the config-driven advisory provider factory. These tests pin the fixes that
/// (a) wire the Configuration battery into the registry, (b) keep node_modules/dist out of
/// findings, (c) suppress template placeholders, and (d) honor a configured advisory feed.
/// </summary>
public class ConfigurationCheckTests
{
    private static IEvidenceFactory Evidence() =>
        new EvidenceFactory(new StandardEvidenceRedactor(RedactionPolicy.Standard));

    // ---------- registry wiring ----------

    [Fact]
    public void CreateRepositoryChecks_IncludesConfigurationBattery()
    {
        var checks = CheckRegistry.CreateRepositoryChecks(Evidence());

        var ids = checks.Select(c => c.Metadata.Id.Value).ToList();
        // Source + dependency + the four configuration checks.
        Assert.Contains("ACT-SRC-SCAN-001", ids);
        Assert.Contains("ACT-DEP-AUDIT-001", ids);
        Assert.Contains("ACT-WEB-CONFIG-001", ids);
        Assert.Contains("ACT-WEB-COMPLIANCE-001", ids);
        Assert.Contains("ACT-WEB-LOGANALYSIS-001", ids);
        Assert.Contains("ACT-WEB-BASELINE-001", ids);
        Assert.Equal(6, checks.Count);
    }

    [Fact]
    public void Catalog_ContainsConfigurationChecks()
    {
        var catalog = CheckRegistry.Catalog();
        var ids = catalog.Select(c => c.Id.Value).ToList();
        Assert.Contains("ACT-WEB-CONFIG-001", ids);
        Assert.Contains("ACT-WEB-COMPLIANCE-001", ids);
        Assert.Contains("ACT-WEB-LOGANALYSIS-001", ids);
        Assert.Contains("ACT-WEB-BASELINE-001", ids);
    }

    // ---------- repository file scanner ----------

    [Fact]
    public void RepositoryFileScanner_ExcludesNodeModulesAndDist()
    {
        using var dir = new SrcDepTempDir();
        // First-party file.
        dir.Write("src/app.env", "TOKEN=real-value");
        // node_modules and dist copies that must be ignored.
        dir.Write("node_modules/fake/lib.env", "TOKEN=should-be-ignored");
        dir.Write("dist/bundle.env", "TOKEN=should-be-ignored");
        dir.Write("frontend/dist/assets/app.env", "TOKEN=should-be-ignored");

        var found = RepositoryFileScanner.FindFiles(dir.Path, "*.env");

        Assert.Single(found);
        Assert.EndsWith(System.IO.Path.Combine("src", "app.env"), found[0]);
        Assert.DoesNotContain("node_modules", found[0]);
        Assert.DoesNotContain("dist", found[0]);
    }

    [Fact]
    public void RepositoryFileScanner_MatchesMultiplePatterns()
    {
        using var dir = new SrcDepTempDir();
        dir.Write("web.config", "x");
        dir.Write("nginx.conf", "x");
        dir.Write("apache.conf", "x");
        dir.Write("c.other", "x");

        var found = RepositoryFileScanner.FindFiles(dir.Path, "web.config", "nginx.conf");

        Assert.Equal(2, found.Count);
        Assert.Contains(found, f => f.EndsWith("web.config"));
        Assert.Contains(found, f => f.EndsWith("nginx.conf"));
    }

    [Fact]
    public void RepositoryFileScanner_ReturnsEmptyForMissingRoot()
    {
        var found = RepositoryFileScanner.FindFiles(System.IO.Path.Combine(Path.GetTempPath(), "definitely-missing-" + Guid.NewGuid().ToString("N")), "*.env");
        Assert.Empty(found);
    }

    // ---------- configuration audit: placeholder suppression ----------

    [Fact]
    public async Task ConfigurationAudit_SkipsPlaceholderSecrets()
    {
        using var dir = new SrcDepTempDir();
        // A template env file with placeholder values only.
        dir.Write("deploy/prod.env", """
            # Real values come from the platform secrets manager.
            POSTGRES_PASSWORD=__set_in_secrets_manager__
            CHATROOM_JWT_SECRET=__set_in_secrets_manager__
            API_TOKEN=${SECRET_REF}
            """);

        var context = SrcDepHarness.CreateContext(dir.Path, Evidence());
        var check = new ConfigurationAuditCheck();
        var result = await check.ExecuteAsync(context, CancellationToken.None);

        Assert.Empty(result.Findings);
    }

    [Fact]
    public async Task ConfigurationAudit_DetectsRealHardcodedCredentials()
    {
        using var dir = new SrcDepTempDir();
        dir.Write("deploy/dev.env", """
            POSTGRES_PASSWORD=chatroom-dev-secret
            CHATROOM_JWT_SECRET=dev-jwt-secret-32-chars-minimum
            """);

        var context = SrcDepHarness.CreateContext(dir.Path, Evidence());
        var check = new ConfigurationAuditCheck();
        var result = await check.ExecuteAsync(context, CancellationToken.None);

        Assert.NotEmpty(result.Findings);
        Assert.All(result.Findings, f =>
            Assert.Equal("Potential Hardcoded Credential", f.Title));
    }

    // ---------- advisory provider factory ----------

    private static IConfiguration BuildConfig(params (string Key, string Value)[] pairs)
    {
        var dict = pairs.ToDictionary(p => p.Key, p => (string?)p.Value);
        return new ConfigurationBuilder().AddInMemoryCollection(dict).Build();
    }

    [Fact]
    public void AdvisoryProviderFactory_ReturnsDisabledWhenNoFeedEnabled()
    {
        var config = BuildConfig(
            ("Act:Feeds:Sources:0:Name", "osv"),
            ("Act:Feeds:Sources:0:Enabled", "false"));

        var provider = AdvisoryProviderFactory.Create(config);

        Assert.IsType<DisabledAdvisoryProvider>(provider);
    }

    [Fact]
    public void AdvisoryProviderFactory_ReturnsOfflineProviderWhenEnabled()
    {
        using var dir = new SrcDepTempDir();
        var feedPath = dir.Write("feed.json", """
            {
              "updatedAt": "2026-01-01T00:00:00Z",
              "packages": [
                { "name": "lodash", "ecosystem": "npm",
                  "advisories": [ { "id": "GHSA-X", "severity": "High",
                    "affectedRange": "<4.17.21", "fixedVersion": "4.17.21" } ] }
              ]
            }
            """);

        var config = BuildConfig(
            ("Act:Feeds:CachePath", dir.Path),
            ("Act:Feeds:Sources:0:Name", "offline"),
            ("Act:Feeds:Sources:0:Kind", "OfflineFile"),
            ("Act:Feeds:Sources:0:EndpointOrPath", feedPath),
            ("Act:Feeds:Sources:0:Enabled", "true"));

        var provider = AdvisoryProviderFactory.Create(config);

        Assert.IsNotType<DisabledAdvisoryProvider>(provider);
        // Wrapped in the caching provider; the name reflects the offline source.
        Assert.Contains("offline", provider.Name, System.StringComparison.OrdinalIgnoreCase);
    }
}
