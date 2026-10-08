using System.Reflection;

namespace ACT.Plugins;

public class PluginLoader
{
    private readonly string _pluginsDirectory;

    public PluginLoader(string pluginsDirectory)
    {
        _pluginsDirectory = pluginsDirectory ?? throw new ArgumentNullException(nameof(pluginsDirectory));
    }

    public List<IPlugin> LoadAllPlugins(PluginContext context)
    {
        var plugins = new List<IPlugin>();

        if (!Directory.Exists(_pluginsDirectory))
        {
            return plugins;
        }

        var dllFiles = Directory.GetFiles(_pluginsDirectory, "*.dll");
        foreach (var dll in dllFiles)
        {
            try
            {
                var assembly = Assembly.LoadFrom(dll);
                var pluginTypes = assembly.GetTypes()
                    .Where(t => typeof(IPlugin).IsAssignableFrom(t) && !t.IsAbstract && !t.IsInterface);

                foreach (var type in pluginTypes)
                {
                    var plugin = (IPlugin)Activator.CreateInstance(type)!;
                    plugin.Initialize(context);
                    plugins.Add(plugin);
                }
            }
            catch (Exception)
            {
                // Log and continue
            }
        }

        return plugins;
    }
}
