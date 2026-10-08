namespace ACT.Plugins;

public interface IPlugin
{
    string Name { get; }
    string Version { get; }
    string Description { get; }
    void Initialize(PluginContext context);
    void Dispose();
}

public class PluginContext
{
    public required PluginLogger Logger { get; init; }
    public required PluginConfiguration Configuration { get; init; }
}

public interface PluginLogger
{
    void Info(string message);
    void Warn(string message);
    void Error(string message);
}

public record PluginConfiguration(
    Dictionary<string, string> Settings);
