using ACT.Auth;
using ACT.Backup;
using ACT.Compliance;
using ACT.Contracts;
using ACT.Encryption;
using ACT.Iac.Checks;
using ACT.Kubernetes.Checks;
using ACT.Reporting.Advanced;
using ACT.Search;
using ACT.Sla;

namespace ACT.Tests;

public class EnterpriseModuleTests
{
    // Auth Tests
    [Fact]
    public void RolePermissions_Should_Have_Admin_All()
    {
        var permissions = RolePermissions.GetPermissionsForRole(Role.Admin);
        Assert.True(permissions.Count > 10);
        Assert.Contains(permissions, p => p.Resource == "assessments" && p.Action == "create");
        Assert.Contains(permissions, p => p.Resource == "findings" && p.Action == "read");
    }

    [Fact]
    public void RolePermissions_Should_Have_Viewer_ReadOnly()
    {
        var permissions = RolePermissions.GetPermissionsForRole(Role.Viewer);
        Assert.True(permissions.Count < 10);
        Assert.Contains(permissions, p => p.Resource == "assessments" && p.Action == "read");
        Assert.DoesNotContain(permissions, p => p.Action == "create");
    }

    // Backup Tests
    [Fact]
    public void DatabaseBackup_Should_Backup_And_List()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), "artemis-test-backup");
        Directory.CreateDirectory(tempDir);
        var dbPath = Path.Combine(tempDir, "test.db");
        File.WriteAllText(dbPath, "test data");

        var backupPath = DatabaseBackup.BackupDatabase(dbPath, tempDir);
        Assert.NotNull(backupPath);
        Assert.True(File.Exists(backupPath));

        var backups = DatabaseBackup.ListBackups(tempDir);
        Assert.Single(backups);

        Directory.Delete(tempDir, true);
    }

    // Compliance Tests
    [Fact]
    public void ComplianceMappingRegistry_Should_Have_Mappings()
    {
        var mappings = ComplianceMappingRegistry.GetMappingsForFramework(ComplianceFramework.SOC2);
        Assert.NotEmpty(mappings);
    }

    [Fact]
    public void ComplianceMappingRegistry_Should_Get_Frameworks_For_Check()
    {
        var frameworks = ComplianceMappingRegistry.GetFrameworksForCheck("ACT-WEB-HSTS-001");
        Assert.Contains(ComplianceFramework.SOC2, frameworks);
        Assert.Contains(ComplianceFramework.HIPAA, frameworks);
    }

    // Encryption Tests
    [Fact]
    public void AesEncryption_Should_Encrypt_And_Decrypt()
    {
        var encryption = AesEncryption.CreateRandom();
        var data = "Hello, World!";
        var encrypted = encryption.EncryptString(data);

        Assert.NotEqual(data, encrypted);

        var decrypted = encryption.DecryptString(encrypted);
        Assert.Equal(data, decrypted);
    }

    // IaC Check Tests
    [Fact]
    public void TerraformCheck_Should_Have_Valid_Metadata()
    {
        var check = new TerraformCheck();
        Assert.NotNull(check.Metadata);
        Assert.Equal("ACT-IAC-TF-001", check.Metadata.Id.Value);
        Assert.Equal(CheckCategory.Iac, check.Metadata.Category);
    }

    // Kubernetes Check Tests
    [Fact]
    public void KubernetesPodSecurityCheck_Should_Have_Valid_Metadata()
    {
        var check = new KubernetesPodSecurityCheck();
        Assert.NotNull(check.Metadata);
        Assert.Equal("ACT-K8S-POD-001", check.Metadata.Id.Value);
        Assert.Equal(CheckCategory.Container, check.Metadata.Category);
    }

    // Reporting Tests
    [Fact]
    public void ExecutiveSummaryGenerator_Should_Generate_Summary()
    {
        var generator = new ExecutiveSummaryGenerator();
        var summary = generator.Generate([]);

        Assert.Equal(0, summary.TotalFindings);
        Assert.Equal("Low", summary.RiskLevel);
    }

    // SLA Tests
    [Fact]
    public void SlaPolicy_Should_Have_Default_Policies()
    {
        var policies = DefaultSlaPolicies.Policies;
        Assert.NotEmpty(policies);
        Assert.Contains(policies, p => p.Severity == Severity.Critical);
        Assert.Contains(policies, p => p.Severity == Severity.High);
        Assert.Contains(policies, p => p.Severity == Severity.Medium);
        Assert.Contains(policies, p => p.Severity == Severity.Low);
        Assert.Contains(policies, p => p.Severity == Severity.Informational);
    }

    // Search Tests
    [Fact]
    public void FindingSearchService_Should_Search()
    {
        var service = new FindingSearchService();
        var query = new FindingSearchQuery(
            Keyword: null,
            MinSeverity: null,
            MaxSeverity: null,
            CheckId: null,
            Asset: null,
            Status: null,
            AssignedTo: null,
            CreatedAfter: null,
            CreatedBefore: null,
            Page: 0,
            PageSize: 10,
            SortBy: null,
            SortDescending: false);

        var result = service.Search([], query);
        Assert.Equal(0, result.TotalCount);
    }
}
