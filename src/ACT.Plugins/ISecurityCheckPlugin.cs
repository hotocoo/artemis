using ACT.Contracts;

namespace ACT.Plugins;

public interface ISecurityCheckPlugin : IPlugin
{
    Task<IReadOnlyList<Finding>> ExecuteAsync(SecurityCheckContext context, CancellationToken cancellationToken);
}
