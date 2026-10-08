using System.Security.Claims;
using System.Text.Json;

namespace ACT.Auth;

public class OAuth2TokenValidator
{
    private readonly string _issuer;
    private readonly string _audience;

    public OAuth2TokenValidator(string issuer, string audience)
    {
        _issuer = issuer ?? throw new ArgumentNullException(nameof(issuer));
        _audience = audience ?? throw new ArgumentNullException(nameof(audience));
    }

    public ClaimsPrincipal? ValidateToken(string token)
    {
        if (string.IsNullOrEmpty(token))
        {
            return null;
        }

        try
        {
            // Simple JWT validation without external library
            var parts = token.Split('.');
            if (parts.Length != 3)
            {
                return null;
            }

            var payloadJson = System.Text.Encoding.UTF8.GetString(
                Convert.FromBase64String(PadBase64(parts[1])));
            var payload = JsonDocument.Parse(payloadJson);

            // Validate issuer
            if (payload.RootElement.TryGetProperty("iss", out var iss) &&
                iss.GetString() != _issuer)
            {
                return null;
            }

            // Validate audience
            if (payload.RootElement.TryGetProperty("aud", out var aud))
            {
                if (aud.ValueKind == JsonValueKind.String && aud.GetString() != _audience)
                {
                    return null;
                }
            }

            // Validate expiration
            if (payload.RootElement.TryGetProperty("exp", out var exp) &&
                exp.GetInt64() < DateTimeOffset.UtcNow.ToUnixTimeSeconds())
            {
                return null;
            }

            return new ClaimsPrincipal(new ClaimsIdentity("jwt"));
        }
        catch
        {
            return null;
        }
    }

    private static string PadBase64(string base64)
    {
        var padding = 4 - (base64.Length % 4);
        if (padding == 4)
        {
            return base64;
        }
        return base64 + new string('=', padding);
    }
}
