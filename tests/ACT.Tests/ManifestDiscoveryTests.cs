using ACT.DependencyAnalysis;
using Xunit;

namespace ACT.Tests;

public class ManifestDiscoveryTests
{
    [Fact]
    public void IsManifestFileName_RecognizesMavenPomXml()
    {
        Assert.True(ManifestParser.IsManifestFileName("pom.xml"));
        Assert.True(ManifestParser.IsManifestFileName("POM.XML"));
        Assert.True(ManifestParser.IsManifestFileName("Pom.Xml"));
    }

    [Fact]
    public void IsManifestFileName_RecognizesGradleBuild()
    {
        Assert.True(ManifestParser.IsManifestFileName("build.gradle"));
        Assert.True(ManifestParser.IsManifestFileName("BUILD.GRADLE"));
        Assert.True(ManifestParser.IsManifestFileName("build.gradle.kts"));
        Assert.True(ManifestParser.IsManifestFileName("Build.Gradle.Kts"));
    }

    [Fact]
    public void EcosystemFor_MapsRecognizedFilesToNonUnknownEcosystem()
    {
        // Every file name that the discovery gate admits must resolve to a real ecosystem so
        // ManifestDiscovery never yields a manifest whose downstream processing treats it as Unknown.
        Assert.Equal(DependencyEcosystem.Maven, ManifestParser.EcosystemFor("pom.xml"));
        Assert.Equal(DependencyEcosystem.Maven, ManifestParser.EcosystemFor("POM.XML"));
        Assert.Equal(DependencyEcosystem.Gradle, ManifestParser.EcosystemFor("build.gradle"));
        Assert.Equal(DependencyEcosystem.Gradle, ManifestParser.EcosystemFor("build.gradle.kts"));
        Assert.Equal(DependencyEcosystem.Gradle, ManifestParser.EcosystemFor("Build.Gradle.Kts"));
    }

    [Fact]
    public void IsManifestFileName_RecognizesAllSupportedFormats()
    {
        Assert.True(ManifestParser.IsManifestFileName("project.csproj"));
        Assert.True(ManifestParser.IsManifestFileName("packages.lock.json"));
        Assert.True(ManifestParser.IsManifestFileName("package-lock.json"));
        Assert.True(ManifestParser.IsManifestFileName("requirements.txt"));
        Assert.True(ManifestParser.IsManifestFileName("Cargo.toml"));
        Assert.True(ManifestParser.IsManifestFileName("CMakeLists.txt"));
        Assert.True(ManifestParser.IsManifestFileName("go.mod"));
        Assert.True(ManifestParser.IsManifestFileName("pom.xml"));
        Assert.True(ManifestParser.IsManifestFileName("build.gradle"));
        Assert.True(ManifestParser.IsManifestFileName("build.gradle.kts"));
    }

    [Fact]
    public void IsManifestFileName_RejectsNonManifests()
    {
        Assert.False(ManifestParser.IsManifestFileName("README.md"));
        Assert.False(ManifestParser.IsManifestFileName("config.json"));
        Assert.False(ManifestParser.IsManifestFileName("settings.xml"));
        Assert.False(ManifestParser.IsManifestFileName("gradle.properties"));
    }
}
