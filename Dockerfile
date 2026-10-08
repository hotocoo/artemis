# Artemis - Autonomous Defensive Security Assessment Platform
# Dockerfile for multi-stage build and optimized production image

# Build stage
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

# Copy solution and project files
COPY Artemis.slnx ./
COPY src/ src/
COPY tests/ tests/

# Restore dependencies
RUN dotnet restore Artemis.slnx -p:NoWarn=NU1900

# Build
RUN dotnet build Artemis.slnx --no-restore -c Release -p:NoWarn=NU1900

# Publish
RUN dotnet publish src/ACT.Cli/ACT.Cli.csproj -c Release -r linux-x64 --self-contained -p:PublishSingleFile=true -p:NoWarn=NU1900 -o /app

# Runtime stage - minimal image
FROM mcr.microsoft.com/dotnet/runtime-deps:10.0 AS runtime
WORKDIR /app

# Create non-root user
RUN addgroup --system --gid 1001 artemis && \
    adduser --system --uid 1001 --ingroup artemis artemis

# Copy published app
COPY --from=build /app /app

# Set ownership
RUN chown -R artemis:artemis /app

# Switch to non-root user
USER artemis

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD /app/artemis doctor || exit 1

# Default command
ENTRYPOINT ["/app/artemis"]
CMD ["--help"]
