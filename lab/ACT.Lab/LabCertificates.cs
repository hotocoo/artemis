using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ACT.Contracts;

namespace ACT.Lab;

/// <summary>Creates the lab's ephemeral self-signed TLS certificates (one modern, one expired).</summary>
public static class LabCertificates
{
    private const string SubjectName = "CN=artemis-lab-selfsigned";

    /// <summary>A self-signed server certificate (RSA-2048, SHA-256) valid for one year.</summary>
    public static X509Certificate2 CreateModernServerCertificate() =>
        Issue(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(365));

    /// <summary>A self-signed server certificate that expired thirty days ago (NotBefore 400 days ago).</summary>
    public static X509Certificate2 CreateExpiredServerCertificate() =>
        Issue(DateTimeOffset.UtcNow.AddDays(-400), DateTimeOffset.UtcNow.AddDays(-30));

    private static X509Certificate2 Issue(DateTimeOffset notBefore, DateTimeOffset notAfter)
    {
        try
        {
            using var key = RSA.Create(2048);
            var request = new CertificateRequest(SubjectName, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, critical: true));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, critical: true));
            var subjectAlternativeNames = new SubjectAlternativeNameBuilder();
            subjectAlternativeNames.AddDnsName("artemis-lab-selfsigned");
            subjectAlternativeNames.AddIpAddress(IPAddress.Loopback);
            request.CertificateExtensions.Add(subjectAlternativeNames.Build());

            using var issued = request.CreateSelfSigned(notBefore, notAfter);

            // Reload through PKCS#12 so the returned certificate detaches from the generation key handle.
            return X509CertificateLoader.LoadPkcs12(issued.Export(X509ContentType.Pfx), password: null);
        }
        catch (Exception failure)
        {
            // Certificate generation is a startup-only boundary; every failure mode here is fatal for
            // the lab and must surface as a categorized, fail-closed configuration error.
            throw ActException.FailClosed(
                ErrorCategory.Configuration,
                "Generating the lab's self-signed TLS certificate failed.",
                $"Subject '{SubjectName}' valid from {notBefore:O} until {notAfter:O} failed: {failure.Message}",
                failure);
        }
    }
}
