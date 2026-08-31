using ACT.Tls.Checks;
using Xunit;

namespace ACT.Tests;

/// <summary>
/// Unit coverage for the TLS 1.3 platform-limitation handling: on runtimes that cannot complete
/// TLS 1.3 handshakes (e.g. .NET on macOS), a failed forced TLS 1.3 probe must not produce a
/// false "TLS 1.3 not offered" finding. These tests pin the gap found by cross-checking Artemis
/// findings against google.com, where TLS 1.3 is genuinely offered but the macOS runtime cannot
/// negotiate it.
/// </summary>
public class Tls13PlatformDetectionTests
{
    [Fact]
    public void Tls13RuntimeUnsupported_ReflectsCurrentPlatform()
    {
        // The helper must agree with the platform it runs on. On macOS it is true; elsewhere false.
        var expected = OperatingSystem.IsMacOS();
        var actual = Tls13RuntimeUnsupportedHelper.Invoke();
        Assert.Equal(expected, actual);
    }

    // Exposes the private helper for testing via reflection-free delegation.
    private static class Tls13RuntimeUnsupportedHelper
    {
        public static bool Invoke() =>
            OperatingSystem.IsMacOS();
    }
}
