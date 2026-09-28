using ACT.SourceAnalysis;
using Xunit;

namespace ACT.Tests;

/// <summary>
/// Unit coverage for the source-rule false-positive reductions: template-literal rejection in the
/// generic-secret validator and test-file exclusion in the rule engine. These pin the accuracy
/// fixes found by cross-checking Artemis findings against the chatroom repository.
/// </summary>
public class SourceRuleFalsePositiveTests
{
    private static SourceRuleEngine EngineFor(string ruleId) =>
        new([DefaultSourceRules.All.First(r => r.RuleId == ruleId)]);

    // ---------- template literal rejection ----------

    [Fact]
    public async Task GenericSecretRule_RejectsTemplateLiteralInterpolation()
    {
        // token=${encodeURIComponent(tok)} is code that resolves to a value, not a literal secret.
        var line = "const url = `?token=${encodeURIComponent(tok)}`";
        var file = new FileContext("src/app.ts", "/tmp/src/app.ts", SourceLanguage.Ts, 100);

        var result = await EngineFor("SRC-SECRET-002").EvaluateAsync(file, StreamLines(line), CancellationToken.None);

        Assert.Empty(result.Matches);
    }

    [Fact]
    public async Task GenericSecretRule_RejectsEnvVariableReference()
    {
        // SECRET=${MY_LONG_ENV_VARIABLE_NAME} is an environment reference, not a literal secret.
        var line = "const SECRET = ${MY_LONG_ENV_VARIABLE_NAME}";
        var file = new FileContext("src/config.ts", "/tmp/src/config.ts", SourceLanguage.Ts, 100);

        var result = await EngineFor("SRC-SECRET-002").EvaluateAsync(file, StreamLines(line), CancellationToken.None);

        Assert.Empty(result.Matches);
    }

    [Fact]
    public async Task GenericSecretRule_StillDetectsRealHighEntropySecret()
    {
        // A genuine high-entropy literal must still be flagged.
        var line = "const password = Xk9#mQ2vL8@nR5tWz3pYb";
        var file = new FileContext("src/config.ts", "/tmp/src/config.ts", SourceLanguage.Ts, 100);

        var result = await EngineFor("SRC-SECRET-002").EvaluateAsync(file, StreamLines(line), CancellationToken.None);

        Assert.NotEmpty(result.Matches);
    }

    // ---------- test file exclusion ----------

    [Theory]
    [InlineData("backend/internal/agent/agent_scope_invariant_test.go")]
    [InlineData("frontend/src/stores/messages.test.ts")]
    [InlineData("frontend/src/stores/messages.spec.ts")]
    [InlineData("tests/test_auth.py")]
    [InlineData("src/ProgramTests.cs")]
    [InlineData("src/__tests__/auth.test.js")]
    [InlineData("src/test_helpers.py")]
    // Kotlin: JUnit (*Test / *Tests) and Spek (*Spec) conventions.
    [InlineData("app/src/test/kotlin/AuthServiceTest.kt")]
    [InlineData("app/src/test/kotlin/AuthServiceTests.kt")]
    [InlineData("app/src/test/kotlin/AuthServiceSpec.kt")]
    // Swift: XCTest (*Tests) and Quick (*Spec) conventions.
    [InlineData("Tests/AuthServiceTests.swift")]
    [InlineData("Spec/AuthServiceSpec.swift")]
    public void IsTestFile_DetectsConventionalTestPaths(string path)
    {
        Assert.True(SourceRuleEngine.IsTestFile(path), "Expected test file: " + path);
    }

    [Theory]
    [InlineData("src/Program.cs")]
    [InlineData("backend/internal/agent/agent.go")]
    [InlineData("src/config.ts")]
    [InlineData("scripts/deploy.sh")]
    public void IsTestFile_IgnoresNonTestPaths(string path)
    {
        Assert.False(SourceRuleEngine.IsTestFile(path), "Expected non-test file: " + path);
    }

    [Theory]
    [InlineData("main.tf")]
    [InlineData("variables.tfvars")]
    public void SourceLanguageDetector_RecognizesInfrastructureFiles(string path)
    {
        Assert.Equal(SourceLanguage.Hcl, SourceLanguageDetector.Detect(path));
    }

    [Theory]
    [InlineData("App.java", SourceLanguage.Java)]
    [InlineData("AuthService.kt", SourceLanguage.Kotlin)]
    [InlineData("AuthService.kts", SourceLanguage.Kotlin)]
    [InlineData("ViewController.swift", SourceLanguage.Swift)]
    [InlineData("index.php", SourceLanguage.Php)]
    [InlineData("app.rb", SourceLanguage.Ruby)]
    [InlineData("main.dart", SourceLanguage.Dart)]
    [InlineData("Main.scala", SourceLanguage.Scala)]
    public void SourceLanguageDetector_RecognizesAdditionalApplicationLanguages(string path, SourceLanguage expected)
    {
        Assert.Equal(expected, SourceLanguageDetector.Detect(path));
    }

    [Fact]
    public async Task GenericSecretRule_SkipsTestFiles()
    {
        // A high-entropy value in a _test.go file must NOT be flagged by the generic rule.
        var line = "const secret = LAUNCH_CODES_XQ7V_PINEAPPLE";
        var file = new FileContext(
            "backend/internal/agent/agent_scope_invariant_test.go",
            "/tmp/backend/internal/agent/agent_scope_invariant_test.go",
            SourceLanguage.Unknown, 100);

        var result = await EngineFor("SRC-SECRET-002").EvaluateAsync(file, StreamLines(line), CancellationToken.None);

        Assert.Empty(result.Matches);
    }

    [Fact]
    public async Task GenericSecretRule_StillScansNonTestFiles()
    {
        // The same value in a non-test file MUST be flagged.
        var line = "const secret = LAUNCH_CODES_XQ7V_PINEAPPLE";
        var file = new FileContext(
            "backend/internal/agent/config.go",
            "/tmp/backend/internal/agent/config.go",
            SourceLanguage.Unknown, 100);

        var result = await EngineFor("SRC-SECRET-002").EvaluateAsync(file, StreamLines(line), CancellationToken.None);

        Assert.NotEmpty(result.Matches);
    }

    [Theory]
    [InlineData("SRC-K8S-020", "  allowPrivilegeEscalation: true", SourceLanguage.Yaml)]
    [InlineData("SRC-DOCKER-025", "RUN curl https://example.invalid/install.sh | sh", SourceLanguage.Dockerfile)]
    [InlineData("SRC-IAC-027", "  cidr_blocks = [\"0.0.0.0/0\"]", SourceLanguage.Hcl)]
    [InlineData("SRC-IAC-028", "  Action: \"*\"", SourceLanguage.Yaml)]
    [InlineData("SRC-CI-033", "pull_request_target:", SourceLanguage.Yaml)]
    [InlineData("SRC-GO-038", "InsecureSkipVerify: true", SourceLanguage.Go)]
    [InlineData("SRC-PY-041", "subprocess.run(command, shell=True)", SourceLanguage.Py)]
    [InlineData("SRC-JS-045", "exec(userCommand)", SourceLanguage.Js)]
    [InlineData("SRC-JVM-060", "ObjectInputStream(stream).readObject()", SourceLanguage.Java)]
    [InlineData("SRC-PHP-063", "eval($_GET['code']);", SourceLanguage.Php)]
    [InlineData("SRC-RUBY-064", "YAML.unsafe_load(input)", SourceLanguage.Ruby)]
    [InlineData("SRC-RUST-050", "danger_accept_invalid_certs(true)", SourceLanguage.Rust)]
    [InlineData("SRC-SHELL-052", "eval \"$user_command\"", SourceLanguage.Shell)]
    [InlineData("SRC-AUTH-058", "redirect(request.query['next'])", SourceLanguage.Py)]
    public async Task ExpandedRules_DetectHighRiskPatterns(string ruleId, string line, SourceLanguage language)
    {
        var file = new FileContext("src/app", "/tmp/src/app", language, line.Length);

        var result = await EngineFor(ruleId).EvaluateAsync(file, StreamLines(line), CancellationToken.None);

        Assert.NotEmpty(result.Matches);
    }

    [Theory]
    [InlineData("SRC-K8S-020", "  allowPrivilegeEscalation: false", SourceLanguage.Yaml)]
    [InlineData("SRC-DOCKER-025", "RUN curl https://example.invalid/install.sh", SourceLanguage.Dockerfile)]
    [InlineData("SRC-IAC-027", "  cidr_blocks = [\"10.0.0.0/8\"]", SourceLanguage.Hcl)]
    [InlineData("SRC-CI-033", "pull_request:", SourceLanguage.Yaml)]
    [InlineData("SRC-GO-038", "InsecureSkipVerify: false", SourceLanguage.Go)]
    [InlineData("SRC-PY-041", "subprocess.run(command, shell=False)", SourceLanguage.Py)]
    [InlineData("SRC-JVM-060", "ObjectInputStream is not used here", SourceLanguage.Java)]
    [InlineData("SRC-RUST-050", "danger_accept_invalid_certs(false)", SourceLanguage.Rust)]
    [InlineData("SRC-SHELL-052", "printf '%s\\n' \"$user_command\"", SourceLanguage.Shell)]
    public async Task ExpandedRules_IgnoreHardenedOrBenignPatterns(string ruleId, string line, SourceLanguage language)
    {
        var file = new FileContext("src/app", "/tmp/src/app", language, line.Length);

        var result = await EngineFor(ruleId).EvaluateAsync(file, StreamLines(line), CancellationToken.None);

        Assert.Empty(result.Matches);
    }

    // ---------- advanced coverage ----------

    [Theory]
    [InlineData("SRC-XXE-016", "var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse };", SourceLanguage.Cs)]
    [InlineData("SRC-XXE-016", "settings.XmlResolver = resolver;", SourceLanguage.Cs)]
    [InlineData("SRC-LDAP-017", "var filter = \"(uid=\" + username + \")\";", SourceLanguage.Cs)]
    [InlineData("SRC-CI-018", "run: echo ${{ github.event.issue.title }}", SourceLanguage.Yaml)]
    [InlineData("SRC-K8S-019", "  privileged: true", SourceLanguage.Yaml)]
    [InlineData("SRC-K8S-019", "  hostNetwork: true", SourceLanguage.Yaml)]
    public async Task AdvancedRules_DetectHighRiskPatterns(string ruleId, string line, SourceLanguage language)
    {
        var file = new FileContext("src/app.cs", "/tmp/src/app.cs", language, line.Length);

        var result = await EngineFor(ruleId).EvaluateAsync(file, StreamLines(line), CancellationToken.None);

        Assert.NotEmpty(result.Matches);
    }

    [Theory]
    [InlineData("SRC-XXE-016", "var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit };", SourceLanguage.Cs)]
    [InlineData("SRC-XXE-016", "settings.XmlResolver = null;", SourceLanguage.Cs)]
    [InlineData("SRC-CI-018", "run: echo ${{ github.sha }}", SourceLanguage.Yaml)]
    [InlineData("SRC-K8S-019", "  privileged: false", SourceLanguage.Yaml)]
    public async Task AdvancedRules_IgnoreHardenedOrBenignPatterns(string ruleId, string line, SourceLanguage language)
    {
        var file = new FileContext("src/app.cs", "/tmp/src/app.cs", language, line.Length);

        var result = await EngineFor(ruleId).EvaluateAsync(file, StreamLines(line), CancellationToken.None);

        Assert.Empty(result.Matches);
    }

    [Theory]
    [InlineData("SRC-WEB-074", "@csrf_exempt", SourceLanguage.Py)]
    [InlineData("SRC-WEB-075", "http.authorizeHttpRequests(a -> a.anyRequest().permitAll());", SourceLanguage.Java)]
    [InlineData("SRC-WEB-076", "cors({ origin: '*', credentials: true });", SourceLanguage.Js)]
    [InlineData("SRC-SSRF-077", "client.get(\"http://169.254.169.254/latest/meta-data/\");", SourceLanguage.Java)]
    [InlineData("SRC-INJECT-078", "return render_template_string(request.args['template']);", SourceLanguage.Py)]
    [InlineData("SRC-DART-079", "Process.runSync('sh', [request.queryParameters['cmd']]);", SourceLanguage.Dart)]
    [InlineData("SRC-SCALA-080", "Runtime.getRuntime().exec(request.getParameter(\"cmd\"));", SourceLanguage.Scala)]
    public async Task ExtendedRules_DetectFrameworkAndBoundaryHazards(string ruleId, string line, SourceLanguage language)
    {
        var file = new FileContext("src/app", "/tmp/src/app", language, line.Length);

        var result = await EngineFor(ruleId).EvaluateAsync(file, StreamLines(line), CancellationToken.None);

        Assert.NotEmpty(result.Matches);
    }

    [Theory]
    [InlineData("SRC-WEB-074", "def view(request): return HttpResponse('ok')", SourceLanguage.Py)]
    [InlineData("SRC-WEB-075", "http.authorizeHttpRequests(a -> a.anyRequest().authenticated());", SourceLanguage.Java)]
    [InlineData("SRC-WEB-076", "cors({ origin: ['https://app.example'], credentials: true });", SourceLanguage.Js)]
    [InlineData("SRC-SSRF-077", "client.get(\"http://service.internal/health\");", SourceLanguage.Java)]
    [InlineData("SRC-INJECT-078", "return render_template('profile.html', user=user);", SourceLanguage.Py)]
    [InlineData("SRC-DART-079", "Process.runSync('sh', ['--version']);", SourceLanguage.Dart)]
    [InlineData("SRC-SCALA-080", "Runtime.getRuntime().exec('/usr/bin/id');", SourceLanguage.Scala)]
    public async Task ExtendedRules_IgnoreHardenedOrBenignPatterns(string ruleId, string line, SourceLanguage language)
    {
        var file = new FileContext("src/app", "/tmp/src/app", language, line.Length);

        var result = await EngineFor(ruleId).EvaluateAsync(file, StreamLines(line), CancellationToken.None);

        Assert.Empty(result.Matches);
    }

    [Fact]
    public void DefaultRules_HaveUniqueIdsAndReachCurrentCoverageBoundary()
    {
        var rules = DefaultSourceRules.All;

        Assert.True(rules.Count >= 110);
        Assert.Equal(rules.Count, rules.Select(r => r.RuleId).Distinct(StringComparer.Ordinal).Count());
        Assert.Contains(rules, r => r.RuleId == "SRC-PHP-110");
    }

    [Theory]
    [InlineData("SRC-WEB-081", "app.run(debug=True)", SourceLanguage.Py)]
    [InlineData("SRC-WEB-082", "DEBUG = True", SourceLanguage.Py)]
    [InlineData("SRC-AUTH-083", "@PreAuthorize(\"permitAll()\")", SourceLanguage.Java)]
    [InlineData("SRC-AUTH-084", "[AllowAnonymous]", SourceLanguage.Cs)]
    [InlineData("SRC-AUTH-085", "validateIssuer = false", SourceLanguage.Cs)]
    [InlineData("SRC-AWS-086", "BlockPublicAcls = false", SourceLanguage.Hcl)]
    [InlineData("SRC-AWS-087", "enable_key_rotation = false", SourceLanguage.Hcl)]
    [InlineData("SRC-AZURE-088", "allow_blob_public_access = true", SourceLanguage.Hcl)]
    [InlineData("SRC-AZURE-089", "purge_protection_enabled = false", SourceLanguage.Hcl)]
    [InlineData("SRC-GCP-090", "member: allUsers", SourceLanguage.Yaml)]
    [InlineData("SRC-GCP-091", "roles/owner", SourceLanguage.Yaml)]
    [InlineData("SRC-K8S-092", "hostPID: true", SourceLanguage.Yaml)]
    [InlineData("SRC-K8S-093", "seccompProfile: type: Unconfined", SourceLanguage.Yaml)]
    [InlineData("SRC-K8S-094", "automountServiceAccountToken: true", SourceLanguage.Yaml)]
    [InlineData("SRC-DOCKER-095", "ADD https://example.invalid/tool /usr/local/bin/tool", SourceLanguage.Dockerfile)]
    [InlineData("SRC-IAC-096", "encrypted = false", SourceLanguage.Hcl)]
    [InlineData("SRC-CI-097", "contents: write", SourceLanguage.Yaml)]
    [InlineData("SRC-AUTH-098", "password == inputPassword", SourceLanguage.Py)]
    [InlineData("SRC-SECRET-099", "readFileSync(privateKeyPath)", SourceLanguage.Js)]
    [InlineData("SRC-SSRF-100", "client.get(\"http://127.0.0.1:8080/admin\")", SourceLanguage.Java)]
    public async Task CurrentCoverageRules_DetectHighRiskPatterns(string ruleId, string line, SourceLanguage language)
    {
        var file = new FileContext("src/app", "/tmp/src/app", language, line.Length);
        var result = await EngineFor(ruleId).EvaluateAsync(file, StreamLines(line), CancellationToken.None);
        Assert.NotEmpty(result.Matches);
    }

    [Theory]
    [InlineData("SRC-WEB-081", "app.run(debug=False)", SourceLanguage.Py)]
    [InlineData("SRC-WEB-082", "DEBUG = False", SourceLanguage.Py)]
    [InlineData("SRC-AUTH-083", "@PreAuthorize(\"hasRole('ADMIN')\")", SourceLanguage.Java)]
    [InlineData("SRC-AUTH-084", "[Authorize]", SourceLanguage.Cs)]
    [InlineData("SRC-AUTH-085", "validateIssuer = true", SourceLanguage.Cs)]
    [InlineData("SRC-AWS-086", "BlockPublicAcls = true", SourceLanguage.Hcl)]
    [InlineData("SRC-AWS-087", "enable_key_rotation = true", SourceLanguage.Hcl)]
    [InlineData("SRC-AZURE-088", "allow_blob_public_access = false", SourceLanguage.Hcl)]
    [InlineData("SRC-AZURE-089", "purge_protection_enabled = true", SourceLanguage.Hcl)]
    [InlineData("SRC-GCP-090", "member: serviceAccount:app@example.iam.gserviceaccount.com", SourceLanguage.Yaml)]
    [InlineData("SRC-GCP-091", "roles/viewer", SourceLanguage.Yaml)]
    [InlineData("SRC-K8S-092", "hostPID: false", SourceLanguage.Yaml)]
    [InlineData("SRC-K8S-093", "type: RuntimeDefault", SourceLanguage.Yaml)]
    [InlineData("SRC-K8S-094", "automountServiceAccountToken: false", SourceLanguage.Yaml)]
    [InlineData("SRC-DOCKER-095", "COPY tool /usr/local/bin/tool", SourceLanguage.Dockerfile)]
    [InlineData("SRC-IAC-096", "encrypted = true", SourceLanguage.Hcl)]
    [InlineData("SRC-CI-097", "contents: read", SourceLanguage.Yaml)]
    [InlineData("SRC-AUTH-098", "password == null", SourceLanguage.Py)]
    [InlineData("SRC-SECRET-099", "readFileSync(serverCertificatePath)", SourceLanguage.Js)]
    [InlineData("SRC-SSRF-100", "client.get(\"https://api.example.com/health\")", SourceLanguage.Java)]
    public async Task CurrentCoverageRules_IgnoreHardenedOrBenignPatterns(string ruleId, string line, SourceLanguage language)
    {
        var file = new FileContext("src/app", "/tmp/src/app", language, line.Length);
        var result = await EngineFor(ruleId).EvaluateAsync(file, StreamLines(line), CancellationToken.None);
        Assert.Empty(result.Matches);
    }

    [Theory]
    [InlineData("SRC-DART-101", "client.badCertificateCallback = (_, __, ___) => true;", SourceLanguage.Dart)]
    [InlineData("SRC-DART-102", "Process.runSync('sh', ['-c', request.cmd]);", SourceLanguage.Dart)]
    [InlineData("SRC-SCALA-103", "factory.setFeature(\"external-general-entities\", true);", SourceLanguage.Scala)]
    [InlineData("SRC-SCALA-104", "val q = sql\"select * from users where id = ${userId}\"", SourceLanguage.Scala)]
    [InlineData("SRC-SWIFT-105", "let trust = serverTrust; acceptCertificate = true", SourceLanguage.Swift)]
    [InlineData("SRC-SWIFT-106", "process.executableURL = URL(fileURLWithPath: \"/bin/sh\"); process.arguments = [\"-c\", request.command]", SourceLanguage.Swift)]
    [InlineData("SRC-PHP-107", "file_get_contents($_GET['url']);", SourceLanguage.Php)]
    [InlineData("SRC-RUBY-108", "YAML.load(params[:payload])", SourceLanguage.Ruby)]
    [InlineData("SRC-RUBY-109", "Open3.capture3(\"sh -c #{params[:cmd]}\")", SourceLanguage.Ruby)]
    [InlineData("SRC-PHP-110", "md5($password)", SourceLanguage.Php)]
    public async Task LanguageSpecificRules_DetectHighRiskPatterns(string ruleId, string line, SourceLanguage language)
    {
        var file = new FileContext("src/app", "/tmp/src/app", language, line.Length);
        var result = await EngineFor(ruleId).EvaluateAsync(file, StreamLines(line), CancellationToken.None);
        Assert.NotEmpty(result.Matches);
    }

    [Theory]
    [InlineData("SRC-DART-101", "client.badCertificateCallback = null;", SourceLanguage.Dart)]
    [InlineData("SRC-DART-102", "Process.runSync('/usr/bin/id', ['--version']);", SourceLanguage.Dart)]
    [InlineData("SRC-SCALA-103", "factory.setFeature(\"external-general-entities\", false);", SourceLanguage.Scala)]
    [InlineData("SRC-SCALA-104", "val q = sql\"select * from users where id = ?\"", SourceLanguage.Scala)]
    [InlineData("SRC-SWIFT-105", "urlSession(_:didReceive:completionHandler:) { completionHandler(.performDefaultHandling) }", SourceLanguage.Swift)]
    [InlineData("SRC-SWIFT-106", "process.executableURL = URL(fileURLWithPath: \"/usr/bin/id\")", SourceLanguage.Swift)]
    [InlineData("SRC-PHP-107", "file_get_contents('https://api.example.com/health');", SourceLanguage.Php)]
    [InlineData("SRC-RUBY-108", "YAML.safe_load(params[:payload], permitted_classes: [])", SourceLanguage.Ruby)]
    [InlineData("SRC-RUBY-109", "Open3.capture3('/usr/bin/id', '--version')", SourceLanguage.Ruby)]
    [InlineData("SRC-PHP-110", "password_hash($password, PASSWORD_ARGON2ID)", SourceLanguage.Php)]
    public async Task LanguageSpecificRules_IgnoreHardenedOrBenignPatterns(string ruleId, string line, SourceLanguage language)
    {
        var file = new FileContext("src/app", "/tmp/src/app", language, line.Length);
        var result = await EngineFor(ruleId).EvaluateAsync(file, StreamLines(line), CancellationToken.None);
        Assert.Empty(result.Matches);
    }

    [Theory]
    [InlineData("SRC-FLOW-111", SourceLanguage.Cs, "var id = Request.Query[\"id\"];", "db.Execute(\"select * from users where id=\" + id);")]
    [InlineData("SRC-FLOW-112", SourceLanguage.Py, "command = request.args.get('cmd')", "subprocess.run(command, shell=True)")]
    [InlineData("SRC-FLOW-113", SourceLanguage.Js, "const file = req.query.file", "fs.readFileSync(file)")]
    [InlineData("SRC-FLOW-114", SourceLanguage.Java, "String url = request.getParameter(\"url\");", "client.get(url);")]
    [InlineData("SRC-FLOW-115", SourceLanguage.Py, "next = request.args.get('next')", "redirect(next)")]
    [InlineData("SRC-FLOW-116", SourceLanguage.Js, "const code = req.body.code", "eval(code)")]
    [InlineData("SRC-FLOW-117", SourceLanguage.Py, "payload = request.body", "pickle.loads(payload)")]
    [InlineData("SRC-FLOW-118", SourceLanguage.Py, "template = request.args.get('template')", "render_template_string(template)")]
    public async Task SemanticFlow_DetectsSourceToSinkAcrossAssignments(string ruleId, SourceLanguage language, string sourceLine, string sinkLine)
    {
        var file = new FileContext("src/app", "/tmp/src/app", language, sourceLine.Length + sinkLine.Length);
        var result = await EngineFor(ruleId).EvaluateAsync(file, StreamLines(sourceLine, sinkLine), CancellationToken.None);

        Assert.Contains(result.Matches, m => m.Rule.RuleId == ruleId && m.LineNumber == 2);
    }

    [Theory]
    [InlineData("SRC-FLOW-111", SourceLanguage.Cs, "var id = Request.Query[\"id\"];", "db.Execute(\"select * from users where id=@id\", new SqlParameter(\"@id\", id));")]
    [InlineData("SRC-FLOW-112", SourceLanguage.Py, "command = request.args.get('cmd')", "subprocess.run([\"/usr/bin/id\", command], shell=False)")]
    [InlineData("SRC-FLOW-113", SourceLanguage.Py, "file = request.args.get('file')", "open(os.path.basename(file))")]
    [InlineData("SRC-FLOW-114", SourceLanguage.Java, "String url = request.getParameter(\"url\");", "client.get(allowlistedUrl(url));")]
    [InlineData("SRC-FLOW-117", SourceLanguage.Py, "payload = request.body", "yaml.safe_load(payload)")]
    public async Task SemanticFlow_RespectsRecognizedSanitizationBoundaries(string ruleId, SourceLanguage language, string sourceLine, string sinkLine)
    {
        var file = new FileContext("src/app", "/tmp/src/app", language, sourceLine.Length + sinkLine.Length);
        var result = await EngineFor(ruleId).EvaluateAsync(file, StreamLines(sourceLine, sinkLine), CancellationToken.None);

        Assert.DoesNotContain(result.Matches, m => m.Rule.RuleId == ruleId && m.LineNumber == 2);
    }

    [Fact]
    public async Task SemanticFlow_DoesNotTreatStringLiteralTextAsTaintedVariable()
    {
        var file = new FileContext("src/app.py", "/tmp/src/app.py", SourceLanguage.Py, 100);
        var result = await EngineFor("SRC-FLOW-111").EvaluateAsync(
            file,
            StreamLines(
                "id = request.args.get('id')",
                "db.execute('select id from users')"),
            CancellationToken.None);

        Assert.Empty(result.Matches);
    }

    [Fact]
    public void DefaultRules_IncludeSemanticFlowBoundary()
    {
        Assert.Equal(130, SourceFlowRules.All.Count + 110);
        Assert.Equal(20, SourceFlowRules.All.Select(r => r.RuleId).Distinct(StringComparer.Ordinal).Count());
        Assert.Equal(130, new SourceRuleEngine().Rules.Count);
    }

    [Theory]
    [InlineData("SRC-FLOW-119", SourceLanguage.Py, "value = request.args.get('uid')", "ldap.search('(uid=' + value + ')')")]
    [InlineData("SRC-FLOW-120", SourceLanguage.Js, "const name = req.query.name", "element.innerHTML = name")]
    [InlineData("SRC-FLOW-121", SourceLanguage.Java, "String next = request.getParameter(\"next\");", "response.setHeader(\"Location\", next);")]
    [InlineData("SRC-FLOW-122", SourceLanguage.Js, "const filter = req.body.filter", "collection.find(filter)")]
    [InlineData("SRC-FLOW-123", SourceLanguage.Js, "const pattern = req.query.pattern", "new RegExp(pattern)")]
    [InlineData("SRC-FLOW-124", SourceLanguage.Java, "String path = request.getParameter(\"path\");", "xpath.evaluate(path, document)")]
    public async Task ExtendedSemanticFlow_DetectsSourceToSink(string ruleId, SourceLanguage language, string sourceLine, string sinkLine)
    {
        var file = new FileContext("src/app", "/tmp/src/app", language, sourceLine.Length + sinkLine.Length);
        var result = await EngineFor(ruleId).EvaluateAsync(file, StreamLines(sourceLine, sinkLine), CancellationToken.None);

        Assert.Contains(result.Matches, m => m.Rule.RuleId == ruleId && m.LineNumber == 2);
    }

    [Theory]
    [InlineData("SRC-FLOW-119", SourceLanguage.Py, "value = request.args.get('uid')", "ldap.search('(uid=' + EscapeFilter(value) + ')')")]
    [InlineData("SRC-FLOW-120", SourceLanguage.Js, "const name = req.query.name", "element.innerHTML = DOMPurify.sanitize(name)")]
    [InlineData("SRC-FLOW-121", SourceLanguage.Java, "String next = request.getParameter(\"next\");", "response.setHeader(\"Location\", validateHeader(next));")]
    [InlineData("SRC-FLOW-122", SourceLanguage.Js, "const filter = req.body.filter", "collection.find(allowlistedFields(filter))")]
    [InlineData("SRC-FLOW-123", SourceLanguage.Js, "const pattern = req.query.pattern", "new RegExp(validatePattern(pattern))")]
    [InlineData("SRC-FLOW-124", SourceLanguage.Java, "String path = request.getParameter(\"path\");", "xpath.evaluate(escapeXPath(path), document)")]
    public async Task ExtendedSemanticFlow_RespectsSanitizationBoundaries(string ruleId, SourceLanguage language, string sourceLine, string sinkLine)
    {
        var file = new FileContext("src/app", "/tmp/src/app", language, sourceLine.Length + sinkLine.Length);
        var result = await EngineFor(ruleId).EvaluateAsync(file, StreamLines(sourceLine, sinkLine), CancellationToken.None);

        Assert.DoesNotContain(result.Matches, m => m.Rule.RuleId == ruleId && m.LineNumber == 2);
    }


    [Fact]
    public async Task SemanticFlow_PropagatesTaintThroughUserFunctionReturn()
    {
        var file = new FileContext("src/app.js", "/tmp/src/app.js", SourceLanguage.Js, 500);
        var result = await EngineFor("SRC-FLOW-111").EvaluateAsync(
            file,
            StreamLines(
                "function passthrough(value) {",
                "  return value;",
                "}",
                "const id = req.query.id;",
                "const queryPart = passthrough(id);",
                "db.execute(\"select * from users where id=\" + queryPart);"),
            CancellationToken.None);

        Assert.Contains(result.Matches, m => m.Rule.RuleId == "SRC-FLOW-111" && m.LineNumber == 6);
    }

    [Fact]
    public async Task SemanticFlow_DoesNotLeakFunctionLocalsIntoSiblingFunction()
    {
        var file = new FileContext("src/app.js", "/tmp/src/app.js", SourceLanguage.Js, 500);
        var result = await EngineFor("SRC-FLOW-111").EvaluateAsync(
            file,
            StreamLines(
                "function first(value) {",
                "  const local = value;",
                "}",
                "function second() {",
                "  db.execute(\"select \" + local);",
                "}"),
            CancellationToken.None);

        Assert.Empty(result.Matches);
    }

    [Fact]
    public async Task SemanticFlow_ResolvesForwardDeclaredReturnWrapper()
    {
        var file = new FileContext("src/app.js", "/tmp/src/app.js", SourceLanguage.Js, 500);
        var result = await EngineFor("SRC-FLOW-111").EvaluateAsync(
            file,
            StreamLines(
                "const id = req.query.id;",
                "const queryPart = passthrough(id);",
                "db.execute(\"select * from users where id=\" + queryPart);",
                "function passthrough(value) {",
                "  return value;",
                "}"),
            CancellationToken.None);

        Assert.Contains(result.Matches, m => m.Rule.RuleId == "SRC-FLOW-111" && m.LineNumber == 3);
    }

    [Fact]
    public async Task SemanticFlow_PropagatesOnlyTheCalleeSinkKind()
    {
        var file = new FileContext("src/app.js", "/tmp/src/app.js", SourceLanguage.Js, 500);
        var result = await EngineFor("SRC-FLOW-112").EvaluateAsync(
            file,
            StreamLines(
                "function run(command) {",
                "  subprocess.run(command, shell=True);",
                "}",
                "const command = req.query.cmd;",
                "run(command);"),
            CancellationToken.None);

        Assert.Contains(result.Matches, m => m.Rule.RuleId == "SRC-FLOW-112" && m.LineNumber == 2);
        Assert.DoesNotContain(result.Matches, m => m.LineNumber == 2 && m.Rule.RuleId != "SRC-FLOW-112");
    }

    [Fact]
    public async Task SemanticFlow_ResolvesUniqueCalleeAcrossFiles()
    {
        var root = Path.Combine(Path.GetTempPath(), "artemis-flow-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var calleePath = Path.Combine(root, "helpers.js");
            var callerPath = Path.Combine(root, "app.js");
            await File.WriteAllLinesAsync(calleePath, [
                "export function runQuery(query) {",
                "  db.execute(query);",
                "}"]);
            await File.WriteAllLinesAsync(callerPath, [
                "const query = req.query.q;",
                "runQuery(query);"]);

            var walker = new RepositoryWalker(root);
            var files = new List<FileContext>();
            await foreach (var entry in walker.WalkAsync())
                if (entry is DiscoveredFile discovered)
                    files.Add(discovered.File);

            var engine = new SourceRuleEngine();
            var catalog = await engine.CollectFunctionCatalogAsync(files, CancellationToken.None);
            var caller = files.Single(f => f.RelativePath.EndsWith("app.js", StringComparison.Ordinal));
            var result = await engine.EvaluateAsync(
                caller, caller.EnumerateLinesAsync(), CancellationToken.None, catalog);

            Assert.Contains(result.Matches, m => m.Rule.RuleId == "SRC-FLOW-111" && m.LineNumber == 2);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task SemanticFlow_DoesNotResolveAmbiguousCalleeAcrossFiles()
    {
        var root = Path.Combine(Path.GetTempPath(), "artemis-flow-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            foreach (var name in new[] { "one.js", "two.js" })
                await File.WriteAllLinesAsync(Path.Combine(root, name), [
                    "export function runQuery(query) {",
                    "  db.execute(query);",
                    "}"]);
            var callerPath = Path.Combine(root, "app.js");
            await File.WriteAllLinesAsync(callerPath, [
                "const query = req.query.q;",
                "runQuery(query);"]);

            var files = new List<FileContext>();
            await foreach (var entry in new RepositoryWalker(root).WalkAsync())
                if (entry is DiscoveredFile discovered)
                    files.Add(discovered.File);

            var engine = new SourceRuleEngine();
            var catalog = await engine.CollectFunctionCatalogAsync(files, CancellationToken.None);
            var caller = files.Single(f => f.RelativePath.EndsWith("app.js", StringComparison.Ordinal));
            var result = await engine.EvaluateAsync(
                caller, caller.EnumerateLinesAsync(), CancellationToken.None, catalog);

            Assert.DoesNotContain(result.Matches, m => m.Rule.RuleId == "SRC-FLOW-111");
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task SemanticFlow_ResolvesMultiHopCrossFileWrapperChain()
    {
        var root = Path.Combine(Path.GetTempPath(), "artemis-flow-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            // Deliberately write the caller first: repository order must not determine propagation.
            await File.WriteAllLinesAsync(Path.Combine(root, "app.js"), [
                "const query = req.query.q;",
                "runQuery(query);"]);
            await File.WriteAllLinesAsync(Path.Combine(root, "middle.js"), [
                "export function runQuery(value) {",
                "  executeQuery(value);",
                "}"]);
            await File.WriteAllLinesAsync(Path.Combine(root, "db.js"), [
                "export function executeQuery(sql) {",
                "  db.execute(sql);",
                "}"]);

            var files = new List<FileContext>();
            await foreach (var entry in new RepositoryWalker(root).WalkAsync())
                if (entry is DiscoveredFile discovered)
                    files.Add(discovered.File);

            var engine = new SourceRuleEngine();
            var catalog = await engine.CollectFunctionCatalogAsync(files, CancellationToken.None);
            var caller = files.Single(f => f.RelativePath.EndsWith("app.js", StringComparison.Ordinal));
            var result = await engine.EvaluateAsync(
                caller, caller.EnumerateLinesAsync(), CancellationToken.None, catalog);

            Assert.Contains(result.Matches, m => m.Rule.RuleId == "SRC-FLOW-111" && m.LineNumber == 2);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task SemanticFlow_PropagatesReturnThroughNestedUserFunctions()
    {
        var file = new FileContext("app.js", "/tmp/app.js", SourceLanguage.Js, 800);
        var result = await EngineFor("SRC-FLOW-111").EvaluateAsync(
            file,
            StreamLines(
                "function inner(value) {",
                "  return value;",
                "}",
                "function outer(value) {",
                "  return inner(value);",
                "}",
                "const id = req.query.id;",
                "const query = outer(id);",
                "db.execute('select ' + query);"),
            CancellationToken.None);

        Assert.Contains(result.Matches, m => m.Rule.RuleId == "SRC-FLOW-111" && m.LineNumber == 9);
    }

    [Fact]
    public async Task SemanticFlow_ResolvesNestedReturnAcrossFiles()
    {
        var root = Path.Combine(Path.GetTempPath(), "artemis-flow-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            await File.WriteAllLinesAsync(Path.Combine(root, "app.js"), [
                "const id = req.query.id;",
                "const query = outer(id);",
                "db.execute('select ' + query);"]);
            await File.WriteAllLinesAsync(Path.Combine(root, "outer.js"), [
                "export function outer(value) {",
                "  return inner(value);",
                "}"]);
            await File.WriteAllLinesAsync(Path.Combine(root, "inner.js"), [
                "export function inner(value) {",
                "  return value;",
                "}"]);

            var files = new List<FileContext>();
            await foreach (var entry in new RepositoryWalker(root).WalkAsync())
                if (entry is DiscoveredFile discovered)
                    files.Add(discovered.File);

            var engine = new SourceRuleEngine();
            var catalog = await engine.CollectFunctionCatalogAsync(files, CancellationToken.None);
            var caller = files.Single(f => f.RelativePath.EndsWith("app.js", StringComparison.Ordinal));
            var result = await engine.EvaluateAsync(caller, caller.EnumerateLinesAsync(), CancellationToken.None, catalog);

            Assert.Contains(result.Matches, m => m.Rule.RuleId == "SRC-FLOW-111" && m.LineNumber == 3);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task SemanticFlow_DoesNotLeakPythonFunctionLocalsIntoTopLevelCode()
    {
        var file = new FileContext("app.py", "/tmp/app.py", SourceLanguage.Py, 500);
        var result = await EngineFor("SRC-FLOW-111").EvaluateAsync(
            file,
            StreamLines(
                "def first(value):",
                "    local = value",
                "    return local",
                "db.execute('select ' + local)"),
            CancellationToken.None);

        Assert.Empty(result.Matches);
    }

    [Fact]
    public async Task SemanticFlow_TracksTaintThroughObjectMemberAssignment()
    {
        var file = new FileContext("app.js", "/tmp/app.js", SourceLanguage.Js, 500);
        var result = await EngineFor("SRC-FLOW-111").EvaluateAsync(
            file,
            StreamLines(
                "const id = req.query.id;",
                "const input = {};",
                "input.id = id;",
                "db.execute('select ' + input.id);"),
            CancellationToken.None);

        Assert.Contains(result.Matches, m => m.Rule.RuleId == "SRC-FLOW-111" && m.LineNumber == 4);
    }

    [Fact]
    public async Task SemanticFlow_HandlesNestedCallArguments()
    {
        var file = new FileContext("app.js", "/tmp/app.js", SourceLanguage.Js, 500);
        var result = await EngineFor("SRC-FLOW-111").EvaluateAsync(
            file,
            StreamLines(
                "function passthrough(value) {",
                "  return value;",
                "}",
                "const id = req.query.id;",
                "db.execute('select ' + passthrough(id));"),
            CancellationToken.None);

        Assert.Contains(result.Matches, m => m.Rule.RuleId == "SRC-FLOW-111" && m.LineNumber == 5);
    }

    [Fact]
    public async Task SemanticFlow_DoesNotFlagUnrelatedTaintedSinkArgument()
    {
        var file = new FileContext("app.py", "/tmp/app.py", SourceLanguage.Py, 500);
        var result = await EngineFor("SRC-FLOW-111").EvaluateAsync(
            file,
            StreamLines(
                "log_message = request.args.get('message')",
                "db.execute('select 1', log_message)"),
            CancellationToken.None);

        Assert.Empty(result.Matches);
    }

    [Fact]
    public async Task SemanticFlow_RecognizesArrowFunctionReturnWrapper()
    {
        var file = new FileContext("app.js", "/tmp/app.js", SourceLanguage.Js, 500);
        var result = await EngineFor("SRC-FLOW-111").EvaluateAsync(
            file,
            StreamLines(
                "const passthrough = (value) => {",
                "  return value;",
                "};",
                "const id = req.query.id;",
                "const query = passthrough(id);",
                "db.execute('select ' + query);"),
            CancellationToken.None);

        Assert.Contains(result.Matches, m => m.Rule.RuleId == "SRC-FLOW-111" && m.LineNumber == 6);
    }

    [Fact]
    public async Task SemanticFlow_StopsTaintAtSqlSanitizerAssignment()
    {
        var file = new FileContext("app.js", "/tmp/app.js", SourceLanguage.Js, 500);
        var result = await EngineFor("SRC-FLOW-111").EvaluateAsync(
            file,
            StreamLines(
                "const id = req.query.id;",
                "const safeId = sqlEscape(id);",
                "db.execute('select ' + safeId);"),
            CancellationToken.None);

        Assert.Empty(result.Matches);
    }

    [Fact]
    public async Task SemanticFlow_StopsTaintAtDirectSqlSanitizer()
    {
        var file = new FileContext("app.js", "/tmp/app.js", SourceLanguage.Js, 500);
        var result = await EngineFor("SRC-FLOW-111").EvaluateAsync(
            file,
            StreamLines("db.execute('select ' + sqlEscape(req.query.id));"),
            CancellationToken.None);

        Assert.Empty(result.Matches);
    }

    [Fact]
    public async Task SemanticFlow_DoesNotTreatHtmlSanitizerAsSqlSanitizer()
    {
        var file = new FileContext("app.js", "/tmp/app.js", SourceLanguage.Js, 500);
        var result = await EngineFor("SRC-FLOW-111").EvaluateAsync(
            file,
            StreamLines(
                "const id = req.query.id;",
                "const safe = DOMPurify.sanitize(id);",
                "db.execute('select ' + safe);"),
            CancellationToken.None);

        Assert.Contains(result.Matches, m => m.Rule.RuleId == "SRC-FLOW-111" && m.LineNumber == 3);
    }

    [Fact]
    public async Task SemanticFlow_UsesSinkSpecificSanitizerBoundary()
    {
        var file = new FileContext("app.js", "/tmp/app.js", SourceLanguage.Js, 500);
        var result = await EngineFor("SRC-FLOW-120").EvaluateAsync(
            file,
            StreamLines(
                "const name = req.query.name;",
                "const safe = DOMPurify.sanitize(name);",
                "element.innerHTML = safe;"),
            CancellationToken.None);

        Assert.DoesNotContain(result.Matches, m => m.Rule.RuleId == "SRC-FLOW-120" && m.LineNumber == 3);
    }

    [Fact]
    public async Task SemanticFlow_PartialSanitizationDoesNotHideAnotherTaintedArgument()
    {
        var file = new FileContext("app.js", "/tmp/app.js", SourceLanguage.Js, 500);
        var result = await EngineFor("SRC-FLOW-111").EvaluateAsync(
            file,
            StreamLines(
                "const id = req.query.id;",
                "const other = req.query.other;",
                "db.execute(sqlEscape(id) + other);"),
            CancellationToken.None);

        Assert.Contains(result.Matches, m => m.Rule.RuleId == "SRC-FLOW-111" && m.LineNumber == 3);
    }

    [Fact]
    public async Task SemanticFlow_NestedSanitizationDoesNotHideTaintOutsideSanitizedExpression()
    {
        var file = new FileContext("app.js", "/tmp/app.js", SourceLanguage.Js, 500);
        var result = await EngineFor("SRC-FLOW-111").EvaluateAsync(
            file,
            StreamLines(
                "const id = req.query.id;",
                "const other = req.query.other;",
                "db.execute(sqlEscape(normalize(id)) + other);"),
            CancellationToken.None);

        Assert.Contains(result.Matches, m => m.Rule.RuleId == "SRC-FLOW-111" && m.LineNumber == 3);
    }

    [Fact]
    public async Task SemanticFlow_DoesNotFlagOnlySanitizedNestedExpression()
    {
        var file = new FileContext("app.js", "/tmp/app.js", SourceLanguage.Js, 500);
        var result = await EngineFor("SRC-FLOW-111").EvaluateAsync(
            file,
            StreamLines(
                "const id = req.query.id;",
                "db.execute('select ' + sqlEscape(normalize(id)));"),
            CancellationToken.None);

        Assert.Empty(result.Matches);
    }

    [Fact]
    public async Task SemanticFlow_TracksJavaScriptDestructuringSources()
    {
        var file = new FileContext("app.js", "/tmp/app.js", SourceLanguage.Js, 500);
        var result = await EngineFor("SRC-FLOW-111").EvaluateAsync(
            file,
            StreamLines(
                "const { id } = req.query;",
                "db.execute('select ' + id);"),
            CancellationToken.None);

        Assert.Contains(result.Matches, m => m.Rule.RuleId == "SRC-FLOW-111" && m.LineNumber == 2);
    }

    [Fact]
    public async Task SemanticFlow_ResolvesImportedFunctionAlias()
    {
        var root = Path.Combine(Path.GetTempPath(), "artemis-flow-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            await File.WriteAllLinesAsync(Path.Combine(root, "db.js"), [
                "export function runQuery(query) {",
                "  db.execute(query);",
                "}"]);
            await File.WriteAllLinesAsync(Path.Combine(root, "app.js"), [
                "import { runQuery as executeQuery } from './db.js';",
                "const query = req.query.q;",
                "executeQuery(query);"]);

            var files = new List<FileContext>();
            await foreach (var entry in new RepositoryWalker(root).WalkAsync())
                if (entry is DiscoveredFile discovered)
                    files.Add(discovered.File);

            var engine = new SourceRuleEngine();
            var catalog = await engine.CollectFunctionCatalogAsync(files, CancellationToken.None);
            var caller = files.Single(f => f.RelativePath.EndsWith("app.js", StringComparison.Ordinal));
            var result = await engine.EvaluateAsync(caller, caller.EnumerateLinesAsync(), CancellationToken.None, catalog);

            Assert.Contains(result.Matches, m => m.Rule.RuleId == "SRC-FLOW-111" && m.LineNumber == 3);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task SemanticFlow_UsesImportedModuleWhenFunctionNameIsDuplicated()
    {
        var root = Path.Combine(Path.GetTempPath(), "artemis-flow-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            await File.WriteAllLinesAsync(Path.Combine(root, "db.js"), [
                "export function runQuery(query) {",
                "  db.execute(query);",
                "}"]);
            await File.WriteAllLinesAsync(Path.Combine(root, "other.js"), [
                "export function runQuery(query) {",
                "  log(query);",
                "}"]);
            await File.WriteAllLinesAsync(Path.Combine(root, "app.js"), [
                "import { runQuery as executeQuery } from './db.js';",
                "const query = req.query.q;",
                "executeQuery(query);"]);

            var files = new List<FileContext>();
            await foreach (var entry in new RepositoryWalker(root).WalkAsync())
                if (entry is DiscoveredFile discovered)
                    files.Add(discovered.File);

            var engine = new SourceRuleEngine();
            var catalog = await engine.CollectFunctionCatalogAsync(files, CancellationToken.None);
            var caller = files.Single(f => f.RelativePath.EndsWith("app.js", StringComparison.Ordinal));
            var result = await engine.EvaluateAsync(caller, caller.EnumerateLinesAsync(), CancellationToken.None, catalog);

            Assert.Contains(result.Matches, m => m.Rule.RuleId == "SRC-FLOW-111" && m.LineNumber == 3);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task SemanticFlow_ResolvesMemberQualifiedCrossFileFunction()
    {
        var root = Path.Combine(Path.GetTempPath(), "artemis-flow-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            await File.WriteAllLinesAsync(Path.Combine(root, "db.js"), [
                "export function runQuery(query) {",
                "  db.execute(query);",
                "}"]);
            await File.WriteAllLinesAsync(Path.Combine(root, "app.js"), [
                "const query = req.query.q;",
                "db.runQuery(query);"]);

            var files = new List<FileContext>();
            await foreach (var entry in new RepositoryWalker(root).WalkAsync())
                if (entry is DiscoveredFile discovered)
                    files.Add(discovered.File);

            var engine = new SourceRuleEngine();
            var catalog = await engine.CollectFunctionCatalogAsync(files, CancellationToken.None);
            var caller = files.Single(f => f.RelativePath.EndsWith("app.js", StringComparison.Ordinal));
            var result = await engine.EvaluateAsync(caller, caller.EnumerateLinesAsync(), CancellationToken.None, catalog);

            Assert.Contains(result.Matches, m => m.Rule.RuleId == "SRC-FLOW-111" && m.LineNumber == 2);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task SemanticFlow_ResolvesNamespaceImportAndCommonJsDestructuring()
    {
        var root = Path.Combine(Path.GetTempPath(), "artemis-flow-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            await File.WriteAllLinesAsync(Path.Combine(root, "db.js"), [
                "export function runQuery(query) {",
                "  db.execute(query);",
                "}"]);
            await File.WriteAllLinesAsync(Path.Combine(root, "app.js"), [
                "const db = require('./db.js');",
                "const query = req.query.q;",
                "db.runQuery(query);"]);

            var files = new List<FileContext>();
            await foreach (var entry in new RepositoryWalker(root).WalkAsync())
                if (entry is DiscoveredFile discovered)
                    files.Add(discovered.File);

            var engine = new SourceRuleEngine();
            var catalog = await engine.CollectFunctionCatalogAsync(files, CancellationToken.None);
            var caller = files.Single(f => f.RelativePath.EndsWith("app.js", StringComparison.Ordinal));
            var result = await engine.EvaluateAsync(caller, caller.EnumerateLinesAsync(), CancellationToken.None, catalog);

            Assert.Contains(result.Matches, m => m.Rule.RuleId == "SRC-FLOW-111" && m.LineNumber == 3);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task SemanticFlow_FailsClosedOnAmbiguousSameFileFunction()
    {
        var file = new FileContext("app.js", "/tmp/app.js", SourceLanguage.Js, 800);
        var result = await EngineFor("SRC-FLOW-111").EvaluateAsync(
            file,
            StreamLines(
                "function run(value) {",
                "  return value;",
                "}",
                "function run(value) {",
                "  return value + 'safe';",
                "}",
                "const id = req.query.id;",
                "const query = run(id);",
                "db.execute('select ' + query);"),
            CancellationToken.None);

        Assert.DoesNotContain(result.Matches, m => m.Rule.RuleId == "SRC-FLOW-111");
    }

    [Theory]
    [InlineData(SourceLanguage.Shell, "cmd=$1", "eval $cmd")]
    [InlineData(SourceLanguage.Go, "cmd := c.Query(\"cmd\")", "exec.Command(\"sh\", \"-c\", cmd)")]
    [InlineData(SourceLanguage.Go, "cmd := r.FormValue(\"cmd\")", "exec.Command(\"sh\", \"-c\", cmd)")]
    [InlineData(SourceLanguage.Py, "cmd = request.args.get('cmd')", "os.system(cmd)")]
    public async Task SemanticFlow_CoversAdditionalFrameworkAndShellSources(
        SourceLanguage language, string sourceLine, string sinkLine)
    {
        var file = new FileContext("app", "/tmp/app", language, 500);
        var result = await EngineFor("SRC-FLOW-112").EvaluateAsync(
            file, StreamLines(sourceLine, sinkLine), CancellationToken.None);

        Assert.Contains(result.Matches, m => m.Rule.RuleId == "SRC-FLOW-112" && m.LineNumber == 2);
    }

    [Theory]
    [InlineData(SourceLanguage.Cs, "void Run([FromQuery] string command)", "Process.Start(command)")]
    [InlineData(SourceLanguage.Java, "void run(@RequestParam String command)", "Runtime.getRuntime().exec(command);")]
    [InlineData(SourceLanguage.Kotlin, "fun run(@RequestParam command: String)", "Runtime.getRuntime().exec(command)")]
    public async Task SemanticFlow_TracksExplicitFrameworkBoundParameters(
        SourceLanguage language, string declaration, string sinkLine)
    {
        var file = new FileContext("app", "/tmp/app", language, 500);
        var result = await EngineFor("SRC-FLOW-112").EvaluateAsync(
            file, StreamLines(declaration, sinkLine), CancellationToken.None);

        Assert.Contains(result.Matches, m => m.Rule.RuleId == "SRC-FLOW-112" && m.LineNumber == 2);
    }

    [Theory]
    [InlineData(SourceLanguage.Go, "func run(r *http.Request) {", "exec.Command(\"sh\", \"-c\", r.FormValue(\"cmd\"))")]
    [InlineData(SourceLanguage.Java, "void run(HttpServletRequest request) {", "Runtime.getRuntime().exec(request.getParameter(\"cmd\"));")]
    [InlineData(SourceLanguage.Cs, "void run(HttpRequest request) {", "Process.Start(request.Query[\"cmd\"]);")]
    public async Task SemanticFlow_RecognizesFrameworkRequestObjectParameterTypes(
        SourceLanguage language, string declaration, string sinkLine)
    {
        var file = new FileContext("app", "/tmp/app", language, 500);
        var result = await EngineFor("SRC-FLOW-112").EvaluateAsync(
            file, StreamLines(declaration, sinkLine, "}"), CancellationToken.None);

        Assert.Contains(result.Matches, m => m.Rule.RuleId == "SRC-FLOW-112" && m.LineNumber == 2);
    }

    [Fact]
    public async Task SemanticFlow_PropagatesQualifiedAsyncFunctionReturn()
    {
        var file = new FileContext("app.ts", "/tmp/app.ts", SourceLanguage.Ts, 500);
        var result = await EngineFor("SRC-FLOW-111").EvaluateAsync(
            file,
            StreamLines(
                "function passthrough(value: string) {",
                "  return value;",
                "}",
                "const id = req.query.id;",
                "const queryPart = await passthrough(id);",
                "db.execute('select ' + queryPart);"),
            CancellationToken.None);

        Assert.Contains(result.Matches, m => m.Rule.RuleId == "SRC-FLOW-111" && m.LineNumber == 6);
    }

    [Theory]
    [InlineData(SourceLanguage.Kotlin, "val command = call.request.queryParameters[\"cmd\"]", "Runtime.getRuntime().exec(command)")]
    [InlineData(SourceLanguage.Scala, "val command = req.uri.query.getOrElse(\"cmd\", \"\")", "Runtime.getRuntime.exec(command)")]
    [InlineData(SourceLanguage.Rust, "fn run(params: web::Query<Input>) {", "Command::new(\"sh\").arg(\"-c\").arg(params.cmd); }")]
    public async Task SemanticFlow_CoversAdditionalModernFrameworkRequestSources(
        SourceLanguage language, string sourceLine, string sinkLine)
    {
        var file = new FileContext("app", "/tmp/app", language, 500);
        var result = await EngineFor("SRC-FLOW-112").EvaluateAsync(
            file, StreamLines(sourceLine, sinkLine), CancellationToken.None);

        Assert.Contains(result.Matches, m => m.Rule.RuleId == "SRC-FLOW-112" && m.LineNumber == 2);
    }

    [Theory]
    [InlineData("SRC-FLOW-111", "const char* id = getenv(\"ID\");", "sqlite3_exec(db, id, callback, nullptr, nullptr);")]
    [InlineData("SRC-FLOW-112", "const char* cmd = getenv(\"CMD\");", "system(cmd);")]
    [InlineData("SRC-FLOW-113", "const char* file = getenv(\"FILE\");", "fopen(file, \"rb\");")]
    [InlineData("SRC-FLOW-116", "const char* code = getenv(\"CODE\");", "luaL_dostring(L, code);")]
    [InlineData("SRC-FLOW-130", "const char* module = getenv(\"MODULE\");", "dlopen(module, RTLD_NOW);")]
    public async Task SemanticFlow_CoversNativeCAndCppSecuritySinks(
        string ruleId, string sourceLine, string sinkLine)
    {
        var file = new FileContext("app.cpp", "/tmp/app.cpp", SourceLanguage.Cpp, 500);
        var result = await EngineFor(ruleId).EvaluateAsync(file, StreamLines(sourceLine, sinkLine), CancellationToken.None);

        Assert.Contains(result.Matches, m => m.Rule.RuleId == ruleId && m.LineNumber == 2);
    }

    [Theory]
    [InlineData("SRC-FLOW-125", SourceLanguage.Java, "String xml = request.getParameter(\"xml\");", "DocumentBuilder.parse(xml);")]
    [InlineData("SRC-FLOW-126", SourceLanguage.Py, "message = request.args.get('message')", "logger.info(message)")]
    [InlineData("SRC-FLOW-127", SourceLanguage.Js, "value = req.query.value", "csvWriter.writeRecord(value)")]
    [InlineData("SRC-FLOW-128", SourceLanguage.Java, "expr = request.getParameter(\"expr\");", "parser.parseExpression(expr)")]
    [InlineData("SRC-FLOW-129", SourceLanguage.Ts, "name = req.query.name", "buildQuery('query { user(name: ' + name + ') }')")]
    [InlineData("SRC-FLOW-130", SourceLanguage.Py, "module = request.args.get('module')", "importlib.import_module(module)")]
    public async Task SemanticFlow_ExpandedSourcesReachNewSecuritySinks(
        string ruleId, SourceLanguage language, string sourceLine, string sinkLine)
    {
        var file = new FileContext("app", "/tmp/app", language, 500);
        var result = await EngineFor(ruleId).EvaluateAsync(file, StreamLines(sourceLine, sinkLine), CancellationToken.None);

        Assert.Contains(result.Matches, m => m.Rule.RuleId == ruleId && m.LineNumber == 2);
    }

    [Theory]
    [InlineData("SRC-FLOW-125", SourceLanguage.Java, "String xml = request.getParameter(\"xml\");", "secureXml.parse(xml);")]
    [InlineData("SRC-FLOW-126", SourceLanguage.Py, "message = request.args.get('message')", "logger.info(sanitizeLog(message))")]
    [InlineData("SRC-FLOW-127", SourceLanguage.Js, "value = req.query.value", "csvWriter.writeRecord(sanitizeCsv(value))")]
    [InlineData("SRC-FLOW-128", SourceLanguage.Java, "expr = request.getParameter(\"expr\");", "parser.parseExpression(allowlistedExpression(expr))")]
    [InlineData("SRC-FLOW-129", SourceLanguage.Ts, "name = req.query.name", "buildQuery(GraphQLVariables(name))")]
    [InlineData("SRC-FLOW-130", SourceLanguage.Py, "module = request.args.get('module')", "importlib.import_module(allowlistedModule(module))")]
    public async Task SemanticFlow_ExpandedSinksRespectSanitizationBoundaries(
        string ruleId, SourceLanguage language, string sourceLine, string sinkLine)
    {
        var file = new FileContext("app", "/tmp/app", language, 500);
        var result = await EngineFor(ruleId).EvaluateAsync(file, StreamLines(sourceLine, sinkLine), CancellationToken.None);

        Assert.DoesNotContain(result.Matches, m => m.Rule.RuleId == ruleId && m.LineNumber == 2);
    }

    // ---------- helper ----------

    private static async IAsyncEnumerable<FileLine> StreamLines(params string[] lines)
    {
        for (var i = 0; i < lines.Length; i++)
        {
            yield return new FileLine(i + 1, lines[i]);
            await Task.Yield();
        }
    }
}
