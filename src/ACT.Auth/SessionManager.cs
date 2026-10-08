using System.Security.Claims;

namespace ACT.Auth;

public class SessionManager
{
    private readonly Dictionary<string, SessionInfo> _sessions = new();
    private readonly TimeSpan _sessionTimeout;

    public SessionManager(TimeSpan sessionTimeout)
    {
        _sessionTimeout = sessionTimeout;
    }

    public string CreateSession(ClaimsPrincipal user)
    {
        var sessionId = Guid.NewGuid().ToString("N");
        _sessions[sessionId] = new SessionInfo(sessionId, user, DateTime.UtcNow);
        return sessionId;
    }

    public SessionInfo? GetSession(string sessionId)
    {
        if (!_sessions.TryGetValue(sessionId, out var session))
        {
            return null;
        }

        if (DateTime.UtcNow - session.LastActivity > _sessionTimeout)
        {
            _sessions.Remove(sessionId);
            return null;
        }

        session.LastActivity = DateTime.UtcNow;
        return session;
    }

    public void RemoveSession(string sessionId)
    {
        _sessions.Remove(sessionId);
    }
}

public record SessionInfo(
    string SessionId,
    ClaimsPrincipal User,
    DateTime CreatedAt)
{
    public DateTime LastActivity { get; set; } = CreatedAt;
}
