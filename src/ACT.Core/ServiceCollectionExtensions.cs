
using ACT.Contracts;
using Microsoft.Extensions.DependencyInjection;

namespace ACT.Core;

/// <summary>DI wiring for the engine core. Composition roots add transport, checks, policy, and stores.</summary>
public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddArtemisCore(this IServiceCollection services)
    {
        services.AddSingleton<AssessmentEngine>();
        services.AddSingleton<Orchestrator>();
        return services;
    }
}
