namespace ACT.Lab;

/// <summary>The canonical good security header set applied to the lab's safe surfaces.</summary>
public static class LabSecurityHeaders
{
    /// <summary>HSTS directive: long max-age with includeSubDomains.</summary>
    public const string StrictTransportSecurity = "max-age=63072000; includeSubDomains";

    /// <summary>Strict deny-everything content security policy used on safe surfaces.</summary>
    public const string ContentSecurityPolicy =
        "default-src 'none'; script-src 'none'; style-src 'none'; img-src 'none'; connect-src 'none'; "
        + "font-src 'none'; media-src 'none'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

    /// <summary>Referrer-Policy value used on safe surfaces.</summary>
    public const string ReferrerPolicy = "strict-origin-when-cross-origin";

    /// <summary>Deny-list Permissions-Policy used on safe surfaces.</summary>
    public const string PermissionsPolicy =
        "accelerometer=(), ambient-light-sensor=(), autoplay=(), battery=(), bluetooth=(), camera=(), "
        + "display-capture=(), encrypted-media=(), geolocation=(), gyroscope=(), interest-cohort=(), "
        + "magnetometer=(), microphone=(), midi=(), payment=(), usb=(), xr-spatial-tracking=()";

    /// <summary>Applies the complete good header set to a response.</summary>
    public static void ApplyGoodSet(HttpResponse response)
    {
        response.Headers.StrictTransportSecurity = StrictTransportSecurity;
        response.Headers.ContentSecurityPolicy = ContentSecurityPolicy;
        response.Headers.XContentTypeOptions = "nosniff";
        response.Headers["Referrer-Policy"] = ReferrerPolicy;
        response.Headers["Permissions-Policy"] = PermissionsPolicy;
        response.Headers.XFrameOptions = "DENY";
    }
}
