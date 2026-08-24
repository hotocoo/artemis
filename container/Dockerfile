# Optional isolated Linux CI image. The Windows single-file exe remains the primary artifact.
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY . .
RUN dotnet publish src/ACT.Cli/ACT.Cli.csproj -c Release -r linux-x64 --self-contained false -o /out

FROM mcr.microsoft.com/dotnet/runtime:10.0
WORKDIR /app
# Run non-root; the scanner needs no privileges for its loopback/local duties.
COPY --from=build /out .
USER app
ENTRYPOINT ["/app/artemis"]
