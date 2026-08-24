
namespace ACT.Contracts;

/// <summary>Kinds of assets an assessment can contain.</summary>
public enum AssetKind
{
    Host,
    Url,
    Repository,
    Container,
    TestEnvironment
}

/// <summary>A discovered or configured asset within one assessment.</summary>
public sealed record AssetRecord(
    Guid AssetId,
    Guid AssessmentId,
    AssetKind Kind,
    string DisplayName,
    string CanonicalTarget,
    IReadOnlyList<string> ObservedIps,
    DateTimeOffset DiscoveredAtUtc,
    bool WithinScope);

/// <summary>An observed network service on an asset.</summary>
public sealed record ServiceObservation(
    Guid ServiceId,
    Guid AssetId,
    int Port,
    ProtocolKind Protocol,
    string? Banner,
    bool TlsNegotiated,
    DateTimeOffset ObservedAtUtc,
    CheckId SourceCheck);

/// <summary>Lifecycle state of an assessment run.</summary>
public enum AssessmentRunState
{
    Created,
    Validating,
    Running,
    Stopping,
    Stopped,
    EmergencyStopped,
    Completed,
    Failed
}

/// <summary>Persisted assessment row.</summary>
public sealed record AssessmentRecord(
    Guid AssessmentId,
    Guid ScopeId,
    string Name,
    AssessmentRunState State,
    DateTimeOffset CreatedUtc,
    DateTimeOffset? StartedUtc,
    DateTimeOffset? CompletedUtc,
    string OperatorIdentity,
    string Organization);

/// <summary>A test principal supplied explicitly by the operator. Credentials never touch persistence.</summary>
public sealed record TestPrincipal(
    string PrincipalId,
    string TenantId,
    string Role,
    IReadOnlyDictionary<string, string> AuthenticationHeaders)
{
    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(PrincipalId) || string.IsNullOrWhiteSpace(TenantId) || string.IsNullOrWhiteSpace(Role))
        {
            throw ActException.FailClosed(ErrorCategory.Configuration,
                "A test principal fixture is missing required identifiers.",
                $"TestPrincipal invalid: PrincipalId='{PrincipalId}', TenantId='{TenantId}', Role='{Role}'.");
        }
        foreach (var header in AuthenticationHeaders.Keys)
        {
            var normalized = header.Trim();
            var allowed = normalized.Equals("Authorization", StringComparison.OrdinalIgnoreCase)
                          || normalized.EndsWith("-header", StringComparison.OrdinalIgnoreCase)
                          || normalized.StartsWith("x-", StringComparison.OrdinalIgnoreCase)
                          || normalized.Equals("Cookie", StringComparison.OrdinalIgnoreCase);
            if (!allowed)
            {
                throw ActException.FailClosed(ErrorCategory.Configuration,
                    "A test principal uses an unsupported authentication header.",
                    $"TestPrincipal '{PrincipalId}' declares non-authentication header '{header}'.");
            }
        }
    }
}

/// <summary>One operator-supplied object used for access-control verification.</summary>
public sealed record ObjectFixture(
    string ObjectId,
    string OwnerTenantId,
    string RelativePathTemplate);

/// <summary>One expected access-control outcome, fully explicit.</summary>
public sealed record AccessExpectation(
    string ExpectationId,
    string PrincipalId,
    string ObjectId,
    string HttpMethod,
    int ExpectedStatusCode,
    string InvariantName);

/// <summary>The complete set of operator-supplied fixtures for authorization testing. Empty set = no authz checks.</summary>
public sealed record AuthorizationFixtureSet(
    IReadOnlyList<TestPrincipal> Principals,
    IReadOnlyList<ObjectFixture> Objects,
    IReadOnlyList<AccessExpectation> Expectations)
{
    public static AuthorizationFixtureSet None { get; } =
        new([], [], []);

    public void Validate()
    {
        var principalIds = Principals.Select(p => p.PrincipalId).ToHashSet(StringComparer.Ordinal);
        var objectIds = Objects.Select(o => o.ObjectId).ToHashSet(StringComparer.Ordinal);
        foreach (var principal in Principals) principal.Validate();
        foreach (var obj in Objects)
        {
            if (string.IsNullOrWhiteSpace(obj.ObjectId) || !obj.RelativePathTemplate.Contains("{id}"))
            {
                throw ActException.FailClosed(ErrorCategory.Configuration,
                    "An object fixture is missing its id or path template.",
                    $"ObjectFixture '{obj.ObjectId}' must reference {{id}} in '{obj.RelativePathTemplate}'.");
            }
        }
        foreach (var expectation in Expectations)
        {
            if (!principalIds.Contains(expectation.PrincipalId) || !objectIds.Contains(expectation.ObjectId))
            {
                throw ActException.FailClosed(ErrorCategory.Configuration,
                    "An access expectation references a principal or object that does not exist.",
                    $"AccessExpectation '{expectation.ExpectationId}' references unknown principal/object.");
            }
            if (expectation.ExpectedStatusCode is < 100 or > 599)
            {
                throw ActException.FailClosed(ErrorCategory.Configuration,
                    "An access expectation has an impossible status code.",
                    $"AccessExpectation '{expectation.ExpectationId}' expects {expectation.ExpectedStatusCode}.");
            }
        }
    }
}
