using System.Text.RegularExpressions;
using ACT.Contracts;

namespace ACT.SourceAnalysis;

/// <summary>Security-relevant taint category tracked by the lightweight source-flow engine.</summary>
public enum SourceTaintKind
{
    Request,
    Environment,
    UserInput,
    FilePath,
    NetworkUrl
}

/// <summary>Built-in semantic source-flow rules. These complement line-oriented declarative rules.</summary>
public static class SourceFlowRules
{
    public static IReadOnlyList<SourceRule> All { get; } =
    [
        FlowRule("SRC-FLOW-111", "Tainted data reaches a SQL execution sink", "SqlInjectionFlow", Severity.Critical,
            "Use parameterized queries and bind values separately from SQL text.",
            "CWE-89", Lang(SourceLanguage.Cs, SourceLanguage.Ts, SourceLanguage.Js, SourceLanguage.Py, SourceLanguage.Go, SourceLanguage.Java, SourceLanguage.Kotlin, SourceLanguage.Rust, SourceLanguage.Cpp, SourceLanguage.Php, SourceLanguage.Ruby, SourceLanguage.Scala)),
        FlowRule("SRC-FLOW-112", "Tainted data reaches a command execution sink", "CommandInjectionFlow", Severity.Critical,
            "Avoid shell execution; pass a fixed executable and an argument vector after strict allowlisting.",
            "CWE-78", Lang(SourceLanguage.Cs, SourceLanguage.Ts, SourceLanguage.Js, SourceLanguage.Py, SourceLanguage.Go, SourceLanguage.Java, SourceLanguage.Kotlin, SourceLanguage.Rust, SourceLanguage.Cpp, SourceLanguage.Php, SourceLanguage.Ruby, SourceLanguage.Dart, SourceLanguage.Scala, SourceLanguage.Swift, SourceLanguage.Shell)),
        FlowRule("SRC-FLOW-113", "Tainted data reaches a filesystem path sink", "PathTraversalFlow", Severity.High,
            "Constrain paths to an intended root and canonicalize/allowlist the resulting path before access.",
            "CWE-22", Lang(SourceLanguage.Cs, SourceLanguage.Ts, SourceLanguage.Js, SourceLanguage.Py, SourceLanguage.Go, SourceLanguage.Java, SourceLanguage.Kotlin, SourceLanguage.Rust, SourceLanguage.Cpp, SourceLanguage.Php, SourceLanguage.Ruby, SourceLanguage.Dart, SourceLanguage.Scala, SourceLanguage.Swift)),
        FlowRule("SRC-FLOW-114", "Tainted data reaches an outbound network request sink", "SsrFflow", Severity.High,
            "Allowlist destinations and schemes; block private, loopback, link-local and metadata networks after DNS resolution.",
            "CWE-918", Lang(SourceLanguage.Cs, SourceLanguage.Ts, SourceLanguage.Js, SourceLanguage.Py, SourceLanguage.Go, SourceLanguage.Java, SourceLanguage.Kotlin, SourceLanguage.Rust, SourceLanguage.Cpp, SourceLanguage.Php, SourceLanguage.Ruby, SourceLanguage.Dart, SourceLanguage.Scala, SourceLanguage.Swift)),
        FlowRule("SRC-FLOW-115", "Tainted data reaches a redirect or Location sink", "OpenRedirectFlow", Severity.High,
            "Use relative redirects or an explicit destination allowlist; never redirect directly to arbitrary user input.",
            "CWE-601", Lang(SourceLanguage.Cs, SourceLanguage.Ts, SourceLanguage.Js, SourceLanguage.Py, SourceLanguage.Go, SourceLanguage.Java, SourceLanguage.Kotlin, SourceLanguage.Cpp, SourceLanguage.Php, SourceLanguage.Ruby, SourceLanguage.Dart, SourceLanguage.Scala, SourceLanguage.Swift)),
        FlowRule("SRC-FLOW-116", "Tainted data reaches a dynamic code-evaluation sink", "CodeExecutionFlow", Severity.Critical,
            "Remove dynamic evaluation; parse data as data and use a constrained interpreter only when unavoidable.",
            "CWE-95", Lang(SourceLanguage.Cs, SourceLanguage.Ts, SourceLanguage.Js, SourceLanguage.Py, SourceLanguage.Cpp, SourceLanguage.Php, SourceLanguage.Ruby, SourceLanguage.Dart, SourceLanguage.Scala)),
        FlowRule("SRC-FLOW-117", "Tainted data reaches an unsafe deserialization sink", "UnsafeDeserializationFlow", Severity.Critical,
            "Use a safe data format/parser with an explicit type allowlist and integrity checks.",
            "CWE-502", Lang(SourceLanguage.Cs, SourceLanguage.Py, SourceLanguage.Java, SourceLanguage.Kotlin, SourceLanguage.Rust, SourceLanguage.Cpp, SourceLanguage.Ruby, SourceLanguage.Php)),
        FlowRule("SRC-FLOW-118", "Tainted data reaches a server-side template sink", "TemplateInjectionFlow", Severity.High,
            "Keep templates trusted and pass untrusted values as data rather than template source.",
            "CWE-1336", Lang(SourceLanguage.Cs, SourceLanguage.Ts, SourceLanguage.Js, SourceLanguage.Py, SourceLanguage.Java, SourceLanguage.Kotlin, SourceLanguage.Ruby, SourceLanguage.Php, SourceLanguage.Go)),
        FlowRule("SRC-FLOW-119", "Tainted data reaches an LDAP query sink", "LdapInjectionFlow", Severity.High,
            "Escape LDAP filter values according to RFC 4515 and keep filter structure separate from user data.",
            "CWE-90", Lang(SourceLanguage.Cs, SourceLanguage.Ts, SourceLanguage.Js, SourceLanguage.Py, SourceLanguage.Java, SourceLanguage.Kotlin, SourceLanguage.Go, SourceLanguage.Php, SourceLanguage.Ruby)),
        FlowRule("SRC-FLOW-120", "Tainted data reaches an HTML or DOM injection sink", "HtmlInjectionFlow", Severity.High,
            "Contextually encode untrusted data or use a trusted HTML sanitizer before inserting it into markup.",
            "CWE-79", Lang(SourceLanguage.Cs, SourceLanguage.Ts, SourceLanguage.Js, SourceLanguage.Py, SourceLanguage.Java, SourceLanguage.Kotlin, SourceLanguage.Php, SourceLanguage.Ruby)),
        FlowRule("SRC-FLOW-121", "Tainted data reaches an HTTP response-header sink", "HttpHeaderInjectionFlow", Severity.High,
            "Validate header values and reject CR/LF characters before writing attacker-controlled data to response headers.",
            "CWE-113", Lang(SourceLanguage.Cs, SourceLanguage.Ts, SourceLanguage.Js, SourceLanguage.Py, SourceLanguage.Java, SourceLanguage.Kotlin, SourceLanguage.Php, SourceLanguage.Ruby, SourceLanguage.Go)),
        FlowRule("SRC-FLOW-122", "Tainted data reaches a NoSQL query sink", "NoSqlInjectionFlow", Severity.High,
            "Build database filters from typed fields and allowlisted operators instead of accepting arbitrary query objects or expressions.",
            "CWE-943", Lang(SourceLanguage.Ts, SourceLanguage.Js, SourceLanguage.Py, SourceLanguage.Java, SourceLanguage.Kotlin, SourceLanguage.Cs, SourceLanguage.Go, SourceLanguage.Ruby, SourceLanguage.Php)),
        FlowRule("SRC-FLOW-123", "Tainted data reaches a regular-expression compilation sink", "RegexInjectionFlow", Severity.High,
            "Treat patterns as trusted code or use a narrowly allowlisted pattern grammar; never compile arbitrary user input as a regex.",
            "CWE-1333", Lang(SourceLanguage.Cs, SourceLanguage.Ts, SourceLanguage.Js, SourceLanguage.Py, SourceLanguage.Java, SourceLanguage.Kotlin, SourceLanguage.Go, SourceLanguage.Rust, SourceLanguage.Php, SourceLanguage.Ruby, SourceLanguage.Dart, SourceLanguage.Scala)),
        FlowRule("SRC-FLOW-124", "Tainted data reaches an XPath query sink", "XPathInjectionFlow", Severity.High,
            "Use parameterized XPath APIs where available or strictly constrain and encode untrusted XPath values.",
            "CWE-643", Lang(SourceLanguage.Cs, SourceLanguage.Java, SourceLanguage.Kotlin, SourceLanguage.Py, SourceLanguage.Php, SourceLanguage.Ruby, SourceLanguage.Js, SourceLanguage.Ts)),
        FlowRule("SRC-FLOW-125", "Tainted data reaches an XML parser with unsafe entity processing", "XxeFlow", Severity.High,
            "Disable DTD and external entity resolution before parsing untrusted XML.",
            "CWE-611", Lang(SourceLanguage.Cs, SourceLanguage.Java, SourceLanguage.Kotlin, SourceLanguage.Py, SourceLanguage.Php, SourceLanguage.Ruby, SourceLanguage.Js, SourceLanguage.Ts, SourceLanguage.Go, SourceLanguage.Rust)),
        FlowRule("SRC-FLOW-126", "Tainted data reaches a log or audit sink without encoding", "LogInjectionFlow", Severity.Medium,
            "Encode or structure untrusted values before writing them to logs so attacker-controlled line breaks and fields cannot forge records.",
            "CWE-117", Lang(SourceLanguage.Cs, SourceLanguage.Java, SourceLanguage.Kotlin, SourceLanguage.Py, SourceLanguage.Php, SourceLanguage.Ruby, SourceLanguage.Js, SourceLanguage.Ts, SourceLanguage.Go, SourceLanguage.Rust)),
        FlowRule("SRC-FLOW-127", "Tainted data reaches a CSV or spreadsheet formula sink", "CsvInjectionFlow", Severity.High,
            "Neutralize spreadsheet formula metacharacters before exporting untrusted values to CSV or spreadsheet formats.",
            "CWE-1236", Lang(SourceLanguage.Cs, SourceLanguage.Java, SourceLanguage.Kotlin, SourceLanguage.Py, SourceLanguage.Php, SourceLanguage.Ruby, SourceLanguage.Js, SourceLanguage.Ts, SourceLanguage.Go)),
        FlowRule("SRC-FLOW-128", "Tainted data reaches an expression-language evaluation sink", "ExpressionInjectionFlow", Severity.Critical,
            "Do not evaluate attacker-controlled expressions; use fixed expressions or a constrained non-executable data representation.",
            "CWE-917", Lang(SourceLanguage.Cs, SourceLanguage.Java, SourceLanguage.Kotlin, SourceLanguage.Py, SourceLanguage.Php, SourceLanguage.Ruby, SourceLanguage.Js, SourceLanguage.Ts)),
        FlowRule("SRC-FLOW-129", "Tainted data reaches a GraphQL query construction sink", "GraphQlInjectionFlow", Severity.High,
            "Use parsed GraphQL documents with allowlisted operations and variables instead of concatenating untrusted input into query syntax.",
            "CWE-89", Lang(SourceLanguage.Cs, SourceLanguage.Java, SourceLanguage.Kotlin, SourceLanguage.Py, SourceLanguage.Js, SourceLanguage.Ts, SourceLanguage.Go)),
        FlowRule("SRC-FLOW-130", "Tainted data reaches a dynamic module or class loading sink", "DynamicLoadingFlow", Severity.High,
            "Load modules and classes only from a trusted allowlist; never derive executable module identifiers directly from untrusted input.",
            "CWE-470", Lang(SourceLanguage.Cs, SourceLanguage.Java, SourceLanguage.Kotlin, SourceLanguage.Py, SourceLanguage.Js, SourceLanguage.Ts, SourceLanguage.Go, SourceLanguage.Cpp, SourceLanguage.Ruby, SourceLanguage.Php))
    ];

    private static SourceRule FlowRule(string id, string title, string findingClass, Severity severity, string remediation, string cwe, IReadOnlyList<SourceLanguage> languages) =>
        new(id, title,
            "The source-flow engine established a path from an untrusted input source to a security-sensitive sink within the analyzed source unit.",
            new RemediationGuidance(remediation, [remediation], [cwe]), findingClass, severity,
            ConfidenceLevel.High, true, languages, 10,
            new Regex("(?!)", RegexOptions.Compiled));

    private static IReadOnlyList<SourceLanguage> Lang(params SourceLanguage[] languages) => languages;
}

/// <summary>
/// Bounded intraprocedural taint analysis. It tracks identifiers through assignments and simple
/// expressions, then checks security-sensitive sinks. It deliberately does not claim interprocedural
/// or type-system precision; the existing pattern rules remain responsible for structural findings.
/// </summary>
public sealed class SourceFlowAnalyzer
{
    private static bool IsFlowSanitizerExpression(string expression, string? ruleId = null)
    {
        var code = CodeWithoutStrings(expression);
        if (!Regex.IsMatch(code, @"\b(?:sqlEscape|escapeSql|sanitize(?:Sql|Html|Query)?|validate(?:Url|Host|Header|Redirect)?|allowlist(?:ed)?|canonicalize|canonicalise|normalize|normalise|escape(?:Shell|Filter|Ldap|Html)?|encode(?:Html|Url)?)\w*\s*\(", RegexOptions.IgnoreCase))
            return false;

        return ruleId switch
        {
            "SRC-FLOW-111" => Regex.IsMatch(code, @"\b(?:parameteri[sz]e|bind(?:Value|Param)|escapeSql|sqlEscape)\w*\s*\(", RegexOptions.IgnoreCase),
            "SRC-FLOW-112" => Regex.IsMatch(code, @"\b(?:escapeShell|shellEscape|allowlist(?:Command|edCommand))\w*\s*\(", RegexOptions.IgnoreCase),
            "SRC-FLOW-113" => Regex.IsMatch(code, @"\b(?:basename|realpath|resolve|canonicalize|canonicalise|safePath|safeFileName)\w*\s*\(", RegexOptions.IgnoreCase),
            "SRC-FLOW-114" => Regex.IsMatch(code, @"\b(?:allowlist(?:ed)?Url|allowlist(?:ed)?Host|validateUrl|validateHost|safeUrl)\w*\s*\(", RegexOptions.IgnoreCase),
            "SRC-FLOW-115" => Regex.IsMatch(code, @"\b(?:allowlist(?:ed)?Redirect|validateRedirect|safeRedirect)\w*\s*\(", RegexOptions.IgnoreCase),
            "SRC-FLOW-116" => false,
            "SRC-FLOW-117" => Regex.IsMatch(code, @"\b(?:safeLoad|allowlist(?:ed)?Type|validatePayload)\w*\s*\(", RegexOptions.IgnoreCase),
            "SRC-FLOW-118" => Regex.IsMatch(code, @"\b(?:sanitize(?:Html|Template)?|escapeHtml|safeTemplate)\w*\s*\(", RegexOptions.IgnoreCase),
            "SRC-FLOW-119" => Regex.IsMatch(code, @"\b(?:escapeFilter|escapeLdap|ldapFilterEscape)\w*\s*\(", RegexOptions.IgnoreCase),
            "SRC-FLOW-120" => Regex.IsMatch(code, @"\b(?:sanitizeHtml|DOMPurify\.sanitize|htmlEncode|escapeHtml)\w*\s*\(", RegexOptions.IgnoreCase),
            "SRC-FLOW-121" => Regex.IsMatch(code, @"\b(?:validateHeader|sanitizeHeader|headerValue)\w*\s*\(", RegexOptions.IgnoreCase),
            "SRC-FLOW-122" => Regex.IsMatch(code, @"\b(?:sanitizeQuery|typedFilter|allowlistedFields|allowedOperators)\w*\s*\(", RegexOptions.IgnoreCase),
            _ => true
        };
    }

    private readonly SourceLanguage _language;
    private readonly SourceFlowFunctionCatalog? _catalog;
    private readonly Dictionary<string, SourceTaintKind> _globalTainted = new(StringComparer.Ordinal);
    private Dictionary<string, SourceTaintKind> _tainted = new(StringComparer.Ordinal);
    private readonly Dictionary<string, FunctionSummary> _taintedFunctions = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, FunctionSummary> _localFunctionSummaries = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _ambiguousLocalFunctions = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, ImportAlias?> _functionAliases = new(StringComparer.OrdinalIgnoreCase);
    private readonly string? _modulePath;
    // Sanitization is sink-specific. A value escaped for HTML is still dangerous when reused as
    // SQL, a shell argument, a path, etc. Keep the taint and attach the sanitizer boundary instead
    // of globally clearing taint from the variable.
    private readonly Dictionary<string, HashSet<string>> _sanitizedVariables = new(StringComparer.Ordinal);
    private readonly List<PendingCall> _pendingCalls = [];
    private string? _currentFunction;
    private int _functionBraceDepth;
    private int _currentFunctionIndent = -1;
    private List<string> _currentParameters = [];
    private string? _pendingRequestHandlerAnnotation;
    private readonly HashSet<int> _currentReturnParameters = [];
    private SourceTaintKind? _currentDirectReturn;
    private readonly Dictionary<int, HashSet<string>> _currentSinkParameters = [];
    private bool _currentFunctionUsesBraces;

    internal sealed record FunctionSummary(
        SourceTaintKind? DirectReturn,
        IReadOnlyList<int> ReturnParameters,
        IReadOnlyDictionary<int, IReadOnlySet<string>> SinkParameters);

    private sealed record PendingCall(
        string FunctionName,
        IReadOnlyList<string> Arguments,
        string? AssignedVariable,
        FileLine Line);

    private sealed record ImportAlias(string Specifier, string ImportedName);

    private static readonly Regex FunctionDeclaration = new(
        @"\b(?:function\s+|(?:(?:public|private|protected|internal|static|async|override|virtual|final|fun|func|fn|def|sub|method)\s+)+(?:[A-Za-z_$][A-Za-z0-9_$<>\[\],.?]*\s+)?|(?:void|bool|boolean|byte|char|short|int|long|float|double|decimal|string|String|object|Object|Task|Task<[^>]+>|Future<[^>]+>|Response|HttpResponse|HttpResult)\s+)(?<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*\((?<params>[^)]*)\)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    private static readonly Regex ReturnStatement = new(
        @"\breturn\s+(?<expr>[^;]+)", RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    private static readonly Regex FunctionCallAssignment = new(
        @"\b(?:var|let|const|val|auto|String|int|long|object|final|def)?\s*(?<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?<call>[A-Za-z_$][A-Za-z0-9_$]*)\s*\((?<args>[^;\r\n]*)\)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex FunctionCall = new(
        @"\b(?<fn>[A-Za-z_$][A-Za-z0-9_$.]*)\s*\((?<args>[^;\r\n]*)\)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex ArrowFunctionDeclaration = new(
        @"\b(?:const|let|var)\s+(?<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:\((?<params>[^)]*)\)|(?<single>[A-Za-z_$][A-Za-z0-9_$]*))\s*=>",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex Assignment = new(
        @"(?:\b(?:var|let|const|val|Dim|String|int|long|auto|char\*|object)\s+)?(?<name>[A-Za-z_$][A-Za-z0-9_$]*(?:\s*\.\s*[A-Za-z_$][A-Za-z0-9_$]*)*)\s*(?:=|:=)\s*(?<expr>[^;]+)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex DestructuringAssignment = new(
        @"\b(?:const|let|var)\s*\{(?<bindings>[^}]+)\}\s*=\s*(?<expr>[^;]+)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex JavaScriptImport = new(
        @"\bimport\s*\{(?<bindings>[^}]+)\}\s*from\s*['""]([^'""]+)['""]",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex PythonImport = new(
        @"\bfrom\s+[A-Za-z_][A-Za-z0-9_.]*\s+import\s+(?<bindings>[^#]+)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    private static readonly Regex JavaScriptNamespaceImport = new(
        @"\bimport\s+\*\s+as\s+(?<local>[A-Za-z_$][A-Za-z0-9_$]*)\s+from\s+['""](?<specifier>[^'""]+)['""]",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex CommonJsDestructuringImport = new(
        @"\b(?:const|let|var)\s*\{(?<bindings>[^}]+)\}\s*=\s*require\(\s*['""](?<specifier>[^'""]+)['""]\s*\)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex CommonJsNamespaceImport = new(
        @"\b(?:const|let|var)\s+(?<local>[A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*require\(\s*['""](?<specifier>[^'""]+)['""]\s*\)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex PythonNamespaceImport = new(
        @"\bimport\s+(?<module>[A-Za-z_][A-Za-z0-9_.]*)(?:\s+as\s+(?<local>[A-Za-z_][A-Za-z0-9_]*))?",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    private static readonly Regex Identifier = new(@"\b[A-Za-z_$][A-Za-z0-9_$]*\b", RegexOptions.Compiled);

    private static readonly Regex[] RequestSources =
    [
        new(@"\b(?:Request\.(?:Query|Form|Headers|Cookies|Path|RouteValues)|HttpContext\.Request\.)", RegexOptions.Compiled | RegexOptions.IgnoreCase),
        new(@"\b(?:req|request|ctx|context)\.(?:query|body|params|form|args|values|headers|cookies|url|originalUrl|queryParams|path|route|searchParams)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase),
        new(@"\b(?:request\.getParameter|request\.getHeader|request\.getQueryString|r\.URL\.Query|r\.FormValue|r\.Header\.Get|params\[|\$_(?:GET|POST|REQUEST|COOKIE)|req\.URL\.Query)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase),
        new(@"\b(?:request\.queryParameters|request\.uri\.queryParameters|HttpRequest\.Query|HttpRequest\.Form|HttpRequest\.Headers)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase),
        new(@"\b(?:call\.request\.(?:queryParameters|headers|cookies)|call\.(?:parameters|request)|req\.uri\.query|req\.uri\.path|request\.url\.queryParameters|request\.url\.path|request\.query\.(?:params|parameters))\b", RegexOptions.Compiled | RegexOptions.IgnoreCase),
        new(@"\b(?:FastAPI|Flask|Django|Express|Koa|Hono|NextRequest|HttpServletRequest|ServerHttpRequest|Gin\.Context|fiber\.Ctx|Echo\.Context|Fiber\.Ctx|HttpExchange|HttpServletRequest)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase),
        new(@"\b(?:c|ctx|context)\.(?:Query|Param|PostForm|FormValue|Body|Cookie|Header|QueryParam|PathParam)\s*\(", RegexOptions.Compiled | RegexOptions.IgnoreCase),
        new(@"\b(?:request|req|r)\.(?:query_params|path_params|headers|cookies|body|json|form|args)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase),
        new(@"\b(?:params|request\.parameters|request\.GET|request\.POST)\s*\[", RegexOptions.Compiled | RegexOptions.IgnoreCase),
        // Common framework accessors that are semantically request-controlled even though they
        // do not use the conventional req/request variable names.
        new(@"\b(?:getQueryParam|getQueryParameter|getPathParam|getPathParameter|getHeader|getCookie|bodyParser|jsonBody|formData|routeParam|routeParameter)\s*\(", RegexOptions.Compiled | RegexOptions.IgnoreCase),
        new(@"\b(?:HttpRequestMessage|IFormCollection|IQueryCollection|RouteData|ActionContext|RequestDelegate|HttpExchange)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase)
    ];

    private static readonly Regex[] EnvironmentSources =
    [
        new(@"\b(?:Environment\.GetEnvironmentVariable|System\.getenv|os\.environ(?:\.get)?|os\.getenv|getenv|std::env::var|process\.env|ENV\[|ENV\.fetch)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase),
        new(@"\b(?:Environment\.GetCommandLineArgs|System\.getProperty|process\.argv|os\.Args|sys\.argv|ARGV)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase)
    ];

    private static readonly Regex[] UserInputSources =
    [
        new(@"\b(?:input\(|Console\.ReadLine\(|readLine\(|bufio\.NewReader|stdin|TextField\(|getText\(|Scanner\.(?:next|nextLine)|BufferedReader\.readLine|std::io::stdin|read_to_string)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase),
        new(@"(?<![A-Za-z0-9_])\$(?:[0-9]+|@|\*|#|\?)\b?", RegexOptions.Compiled)
    ];

    // Explicit framework parameter binders are request sources even when the handler body never
    // reads Request/req/request directly. Ordinary function parameters remain untainted.
    private static readonly Regex RequestBoundParameterMarkers = new(
        @"\b(?:FromQuery|FromRoute|FromBody|FromForm|FromHeader|RequestParam|RequestHeader|RequestBody|PathVariable|MatrixVariable|QueryParam|QueryParameter|BodyParam|FormParam|PathParam|CookieValue|HeaderParam|web::(?:Query|Path|Json|Form))\b",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    // Framework-populated request objects are sources even when the handler never reads a
    // conventional request variable. This is intentionally type-based to avoid tainting every
    // ordinary parameter named `request`/`ctx` in application code.
    private static readonly Regex RequestParameterTypes = new(
        @"\b(?:HttpRequest|HttpRequestMessage|HttpContext|IHttpRequest|HttpServletRequest|ServletRequest|ServerHttpRequest|ServerRequest|WebRequest|ClientRequest|IncomingMessage|Request|\*http\.Request|http\.Request|gin\.Context|\*gin\.Context|fiber\.Ctx|\*fiber\.Ctx|echo\.Context|\*echo\.Context)\b",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    // Route decorators/attributes are often on the line before the handler declaration.
    private static readonly Regex RequestHandlerAnnotations = new(
        @"(?:\[(?:HttpGet|HttpPost|HttpPut|HttpPatch|HttpDelete|Route|ApiController)\b|@(?:RequestMapping|GetMapping|PostMapping|PutMapping|PatchMapping|DeleteMapping|HttpExchange|GetExchange|PostExchange)\b|@(?:app|router|blueprint|bp)\.(?:route|get|post|put|patch|delete)\b)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    private static readonly Regex[] SqlSinks =
    [
        new(@"\b(?:Execute(?:NonQuery|Scalar|Reader)?|exec(?:ute)?|query|raw|rawQuery|createNativeQuery|FromSql(?:Raw|Interpolated)?|ExecuteSql(?:Raw|Interpolated)?|SqlQuery(?:Raw)?|mysql_query|sqlite3_exec|PQexec|SQLExecDirect|JdbcTemplate\.(?:query|update)|Statement\.execute(?:Query|Update)?)\s*\(", RegexOptions.Compiled | RegexOptions.IgnoreCase),
        new(@"\b(?:cursor|db|database|connection|conn|tx|transaction)\.(?:execute|executemany|raw|query)\s*\(", RegexOptions.Compiled | RegexOptions.IgnoreCase),
        new(@"\b(?:sequelize|knex|gorm|sqlx|Diesel|EntityManager|JdbcTemplate|jooq|DSL)\.(?:query|raw|execute|fetch|fetchOne)\s*\(", RegexOptions.Compiled | RegexOptions.IgnoreCase)
    ];

    private static readonly Regex[] CommandSinks =
    [
        new(@"\b(?:system|popen|exec|spawn|Process\.Start|Process\.Run|Process\.runSync|child_process\.(?:exec|execSync|spawn|spawnSync)|subprocess\.(?:run|Popen|call|check_call|check_output|check_output)|Runtime\.getRuntime\(\)\.exec|Open3\.(?:capture[23]|popen[23])|ShellCommand|CommandRunner\.run)\s*\(", RegexOptions.Compiled | RegexOptions.IgnoreCase),
        new(@"\b(?:Command|CommandLine)\s*\(", RegexOptions.Compiled | RegexOptions.IgnoreCase),
        new(@"\b(?:std::process::)?Command::new\s*\(", RegexOptions.Compiled | RegexOptions.IgnoreCase),
        new(@"(?<![A-Za-z0-9_])(?:eval|source)\s+\$", RegexOptions.Compiled | RegexOptions.IgnoreCase),
        new(@"(?<![A-Za-z0-9_])(?:bash|sh|zsh|dash|ksh)\s+-c\s+", RegexOptions.Compiled | RegexOptions.IgnoreCase),
        new(@"(?<![A-Za-z0-9_])(?:xargs|env)\s+", RegexOptions.Compiled | RegexOptions.IgnoreCase)
    ];

    private static readonly Regex[] PathSinks =
    [
        new(@"\b(?:File\.(?:Open|ReadAllText|WriteAllText|Delete|Copy|Move|ReadAllBytes|WriteAllBytes)|FileStream|File\.OpenRead|File\.OpenWrite|open|fopen|freopen|readFile(?:Sync)?|writeFile(?:Sync)?|unlink(?:Sync)?|remove|rename|os\.(?:open|remove|rename)|Path\.new|Files\.(?:read|write|delete|newInputStream|newOutputStream)|Directory\.(?:Delete|Move|CreateDirectory))\s*\(", RegexOptions.Compiled | RegexOptions.IgnoreCase),
        new(@"\b(?:send_file|send_from_directory|render_template|include|require|fs\.(?:open|access|stat|mkdir|rm|cp|mv|readFile|writeFile)|path\.resolve|path\.join|tempfile\.(?:NamedTemporaryFile|mktemp)|TarArchive|ZipFile)\s*\(", RegexOptions.Compiled | RegexOptions.IgnoreCase)
    ];

    private static readonly Regex[] UrlSinks =
    [
        new(@"\b(?:HttpClient|WebClient|WebRequest|fetch|axios\.(?:get|post|put|delete|request)|requests\.(?:get|post|put|delete|request)|urllib\.request\.urlopen|http\.(?:Get|Post)|client\.(?:get|post|request)|URLSession|Dio\.(?:get|post)|OkHttpClient|RestTemplate|WebClient|HttpURLConnection|Net::HTTP|Faraday)\s*", RegexOptions.Compiled | RegexOptions.IgnoreCase)
    ];

    private static readonly Regex[] RedirectSinks =
    [
        new(@"\b(?:Redirect|redirect|RedirectToAction|sendRedirect|location\.assign|location\.replace|res\.redirect|Response\.Redirect)\s*\(", RegexOptions.Compiled | RegexOptions.IgnoreCase),
        new(@"\bLocation\s*[:=]", RegexOptions.Compiled | RegexOptions.IgnoreCase)
    ];

    private static readonly Regex[] EvalSinks =
    [
        new(@"\b(?:eval|exec|execfile|compile|Function|vm\.run(?:InNewContext|InContext)?|Expression\.Compile|ScriptEngine\.eval|Kernel\.eval|instance_eval|PyRun_SimpleString|luaL_dostring|luaL_loadstring)\s*\(", RegexOptions.Compiled | RegexOptions.IgnoreCase)
    ];

    private static readonly Regex[] DeserializeSinks =
    [
        new(@"\b(?:BinaryFormatter|NetDataContractSerializer|ObjectInputStream|readObject|pickle\.(?:load|loads)|yaml\.(?:load|unsafe_load)|YAML\.load|unserialize|Marshal\.load|bincode::deserialize|JsonConvert\.DeserializeObject)\s*", RegexOptions.Compiled | RegexOptions.IgnoreCase)
    ];

    private static readonly Regex[] TemplateSinks =
    [
        new(@"\b(?:render_template_string|Template|Jinja2\.Template|twig(?:\.createTemplate)?|Handlebars\.compile|Mustache\.render|VelocityEngine|FreeMarker)\s*\(", RegexOptions.Compiled | RegexOptions.IgnoreCase)
    ];

    private static readonly Regex[] LdapSinks =
    [
        new(@"\b(?:DirectorySearcher|SearchRequest|LdapConnection|ldapsearch|LDAPSearch|search)\s*\(", RegexOptions.Compiled | RegexOptions.IgnoreCase),
        new(@"\b(?:ldap|directory|connection)\.(?:search|search_s|search_ext)\s*\(", RegexOptions.Compiled | RegexOptions.IgnoreCase)
    ];

    private static readonly Regex[] HtmlSinks =
    [
        new(@"\b(?:innerHTML|outerHTML)\s*=", RegexOptions.Compiled | RegexOptions.IgnoreCase),
        new(@"\b(?:insertAdjacentHTML|document\.write|document\.writeln)\s*\(", RegexOptions.Compiled | RegexOptions.IgnoreCase),
        new(@"\bdangerouslySetInnerHTML\s*=", RegexOptions.Compiled | RegexOptions.IgnoreCase)
    ];

    private static readonly Regex[] HeaderSinks =
    [
        new(@"\b(?:setHeader|addHeader|appendHeader|setResponseHeader)\s*\(", RegexOptions.Compiled | RegexOptions.IgnoreCase),
        new(@"\b(?:response|res|reply|headers?)\.(?:set|append|add|setHeader)\s*\(", RegexOptions.Compiled | RegexOptions.IgnoreCase)
    ];

    private static readonly Regex[] NoSqlSinks =
    [
        new(@"\b(?:find|findOne|findOneAndUpdate|findOneAndDelete|aggregate|updateMany|deleteMany)\s*\(", RegexOptions.Compiled | RegexOptions.IgnoreCase),
        new(@"\b(?:collection|db|model|mongoose|mongo)\.(?:find|findOne|aggregate|updateMany|deleteMany)\s*\(", RegexOptions.Compiled | RegexOptions.IgnoreCase)
    ];

    private static readonly Regex[] RegexSinks =
    [
        new(@"\b(?:new\s+RegExp|RegExp|Regex|new\s+Regex|Pattern\.compile|regexp\.(?:Compile|MustCompile)|Regex\.new|Regexp\.new)\s*\(", RegexOptions.Compiled | RegexOptions.IgnoreCase),
        new(@"\b(?:NSRegularExpression|NSRegularExpression\.regularExpression)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase)
    ];

    private static readonly Regex[] XPathSinks =
    [
        new(@"\b(?:XPathExpression|XPathNavigator|XPathNodeIterator|selectNodes|selectSingleNode|evaluate|evaluateExpression|XPathFactory|XPath\.new)\s*\(", RegexOptions.Compiled | RegexOptions.IgnoreCase),
        new(@"\b(?:xpath|xml)\.(?:find|select|evaluate)\s*\(", RegexOptions.Compiled | RegexOptions.IgnoreCase)
    ];

    private static readonly Regex[] XxeSinks =
    [
        new(@"\b(?:XmlReader\.Create|XDocument\.Parse|XmlDocument\.Load|DocumentBuilder\.parse|SAXBuilder\.build|etree\.parse|fromstring|DOMParser\.parseFromString)\s*\(", RegexOptions.Compiled | RegexOptions.IgnoreCase),
        new(@"\b(?:XmlReader|DocumentBuilderFactory|SAXParserFactory|XMLParser|DOMParser)\b[^\n]*(?:Parse|parse|load|read)\s*\(", RegexOptions.Compiled | RegexOptions.IgnoreCase)
    ];

    private static readonly Regex[] LogSinks =
    [
        new(@"\b(?:Console\.(?:Write|WriteLine)|logger?\.(?:trace|debug|info|warn|warning|error|fatal|log)|Logger\.(?:log|info|warn|error)|logging\.(?:debug|info|warning|error|critical)|log4j?\.(?:debug|info|warn|error|fatal)|Serilog\.(?:Information|Warning|Error|Fatal)|zap\.(?:Debug|Info|Warn|Error)|slog\.(?:Debug|Info|Warn|Error))\s*\(", RegexOptions.Compiled | RegexOptions.IgnoreCase)
    ];

    private static readonly Regex[] CsvSinks =
    [
        new(@"\b(?:CsvWriter|CSVWriter|csvWriter|writeRecord|WriteField|appendRow|worksheet\.(?:append|write)|sheet\.(?:append|write))\s*\(", RegexOptions.Compiled | RegexOptions.IgnoreCase)
    ];

    private static readonly Regex[] ExpressionSinks =
    [
        new(@"\b(?:SpelExpressionParser|ExpressionParser|parseExpression|evaluateExpression|MVEL|OGNL|ELProcessor|ScriptEngine|evalExpression|Expression\.evaluate|jexl\.(?:createExpression|evaluate))\s*\(", RegexOptions.Compiled | RegexOptions.IgnoreCase)
    ];

    private static readonly Regex[] GraphQlSinks =
    [
        new(@"\b(?:build(?:Query|Mutation)|create(?:Query|Mutation)|gql)\s*\(", RegexOptions.Compiled | RegexOptions.IgnoreCase),
        new(@"\b(?:GraphQLRequest|GraphQLQuery|GraphQLClient)\s*\([^\n]*(?:\+|\$\{|String\.format|format\s*\()", RegexOptions.Compiled | RegexOptions.IgnoreCase)
    ];

    private static readonly Regex[] DynamicLoadingSinks =
    [
        new(@"\b(?:Class\.forName|Assembly\.Load(?:From|File)?|Type\.GetType|importlib\.import_module|__import__|require|require_relative|dlopen|LoadLibrary|LoadLibraryEx|reflect\.New|ClassLoader)\s*\(", RegexOptions.Compiled | RegexOptions.IgnoreCase)
    ];

    public SourceFlowAnalyzer(SourceLanguage language, SourceFlowFunctionCatalog? catalog = null, string? modulePath = null)
    {
        _language = language;
        _catalog = catalog;
        _modulePath = modulePath;
        if (catalog is not null)
            foreach (var pair in catalog.UniqueFunctions)
                _taintedFunctions[pair.Key] = pair.Value;
    }

    internal IReadOnlyDictionary<string, FunctionSummary> FunctionSummaries => _localFunctionSummaries;

    /// <summary>Resolves forward-declared calls after the complete source unit has streamed.</summary>
    public IReadOnlyList<SourceRuleMatch> FinalizeAnalysis()
    {
        var results = new List<SourceRuleMatch>();
        var changed = true;
        var passes = 0;
        while (changed && passes++ < 16)
        {
            changed = false;
            foreach (var call in _pendingCalls)
            {
                if (!_taintedFunctions.TryGetValue(call.FunctionName, out var summary)) continue;

                if (call.AssignedVariable is not null && ResolveCallReturnTaint(summary, call.Arguments) is { } taint &&
                    (!_tainted.TryGetValue(call.AssignedVariable, out var old) || old != taint))
                {
                    _tainted[call.AssignedVariable] = taint;
                    changed = true;
                }

                foreach (var pair in summary.SinkParameters)
                {
                    if (pair.Key >= call.Arguments.Count || !TryGetTaint(call.Arguments[pair.Key], out _)) continue;
                    foreach (var ruleId in pair.Value)
                    {
                        if (results.Any(m => m.Rule.RuleId == ruleId && m.LineNumber == call.Line.Number)) continue;
                        var rule = SourceFlowRules.All.First(r => r.RuleId == ruleId);
                        results.Add(new SourceRuleMatch(rule, call.Line.Number, call.Line.Text, call.Arguments[pair.Key]));
                    }
                }
            }
        }
        return results;
    }

    /// <summary>Processes one source line and returns semantic sink matches for that line.</summary>
    public IReadOnlyList<SourceRuleMatch> Analyze(FileLine line)
    {
        var results = new List<SourceRuleMatch>();
        var text = line.Text;
        var code = CodeWithoutStrings(text);
        var trimmed = text.TrimStart();
        if (trimmed.StartsWith("//", StringComparison.Ordinal) || trimmed.StartsWith("#", StringComparison.Ordinal) ||
            trimmed.StartsWith("/*", StringComparison.Ordinal) || trimmed.StartsWith("*", StringComparison.Ordinal))
            return results;

        TrackFunctionContext(code);
        TrackModuleImports(text);

        // A caller may precede its callee. Once the callee has been discovered, materialize any
        // deferred return taint before evaluating the current line's sinks.
        ResolvePendingAssignments();

        foreach (Match assignment in Assignment.Matches(code))
        {
            var name = assignment.Groups["name"].Value;
            var expr = assignment.Groups["expr"].Value;
            // Evaluate the complete assignment as well as the RHS. This handles typed/indexed
            // request expressions such as Request.Query["id"] without depending on how a language
            // lexer tokenizes the surrounding declaration.
            var normalizedName = NormalizeExpression(name);
            var source = SourceKind(expr) ?? SourceKind(text);
            if (IsFlowSanitizerExpression(expr) || IsKnownSanitizerCall(expr))
            {
                _sanitizedVariables[normalizedName] = SanitizerKinds(expr);
                var sanitizedSource = source;
                if (!sanitizedSource.HasValue && ContainsTaintedIdentifier(expr))
                    sanitizedSource = FirstTaint(expr);
                if (sanitizedSource.HasValue)
                {
                    _tainted[normalizedName] = sanitizedSource.Value;
                    if (_currentFunction is null)
                        _globalTainted[normalizedName] = sanitizedSource.Value;
                }
                else
                {
                    _tainted.Remove(normalizedName);
                    if (_currentFunction is null)
                        _globalTainted.Remove(normalizedName);
                }
            }
            else if (source.HasValue)
            {
                _sanitizedVariables.Remove(normalizedName);
                _tainted[normalizedName] = source.Value;
                if (_currentFunction is null)
                    _globalTainted[normalizedName] = source.Value;
            }
            else if (TryTaintedFunctionCall(expr, out var functionTaint, name, line))
            {
                _sanitizedVariables.Remove(normalizedName);
                _tainted[NormalizeExpression(name)] = functionTaint;
                if (_currentFunction is null)
                    _globalTainted[NormalizeExpression(name)] = functionTaint;
            }
            else if (ContainsAmbiguousFunctionCall(expr))
            {
                // An ambiguous overload is deliberately a hard resolution boundary. Do not let
                // the argument itself taint the return value merely because it appears inside an
                // unresolved call; that would defeat fail-closed call resolution.
                _sanitizedVariables.Remove(normalizedName);
                _tainted.Remove(normalizedName);
                if (_currentFunction is null)
                    _globalTainted.Remove(normalizedName);
            }
            else if (ContainsTaintedIdentifier(expr))
            {
                _sanitizedVariables.Remove(normalizedName);
                _tainted[NormalizeExpression(name)] = FirstTaint(expr);
                if (_currentFunction is null)
                    _globalTainted[NormalizeExpression(name)] = _tainted[NormalizeExpression(name)];
            }
            else
            {
                _sanitizedVariables.Remove(normalizedName);
                _tainted.Remove(NormalizeExpression(name));
                if (_currentFunction is null)
                    _globalTainted.Remove(NormalizeExpression(name));
            }
        }

        foreach (Match destructuring in DestructuringAssignment.Matches(code))
        {
            var rhs = destructuring.Groups["expr"].Value;
            var source = SourceKind(rhs);
            var tainted = source ?? (ContainsTaintedIdentifier(rhs) ? FirstTaint(rhs) : null);
            if (!tainted.HasValue)
                continue;

            foreach (var binding in destructuring.Groups["bindings"].Value.Split(',', StringSplitOptions.RemoveEmptyEntries))
            {
                var parts = binding.Split(':', 2, StringSplitOptions.TrimEntries);
                var name = parts[^1].Trim();
                if (!Identifier.IsMatch(name))
                    continue;
                var normalizedName = NormalizeExpression(name);
                _tainted[normalizedName] = tainted.Value;
                _sanitizedVariables.Remove(normalizedName);
                if (_currentFunction is null)
                    _globalTainted[normalizedName] = tainted.Value;
            }
        }

        foreach (Match call in FunctionCallAssignment.Matches(code))
        {
            if (TryTaintedFunctionCall(call.Value, out var functionTaint, call.Groups["name"].Value, line))
                _tainted[NormalizeExpression(call.Groups["name"].Value)] = functionTaint;
        }

        var returnMatch = ReturnStatement.Match(code);
        if (_currentFunction is not null && returnMatch.Success)
        {
            var returnExpression = returnMatch.Groups["expr"].Value;
            var returnTaint = SourceKind(returnExpression);
            if (!returnTaint.HasValue && ContainsTaintedIdentifier(returnMatch.Groups["expr"].Value))
                returnTaint = FirstTaint(returnMatch.Groups["expr"].Value);

            // A wrapper can return another wrapper's result (for example
            // `return loadUser(id);`). Resolve that call against the current catalog so
            // interprocedural return propagation reaches a sink through arbitrarily ordered,
            // bounded summary passes instead of stopping at one function boundary.
            if (!returnTaint.HasValue && TryResolveReturnCall(returnExpression, out var callTaint, out var callParameters))
            {
                returnTaint = callTaint;
                foreach (var index in callParameters)
                    _currentReturnParameters.Add(index);
            }
            if (returnTaint.HasValue)
                _currentDirectReturn = returnTaint.Value;
            foreach (var index in ParameterIndices(returnMatch.Groups["expr"].Value))
                _currentReturnParameters.Add(index);
        }

        // Declaration syntax varies considerably across the supported languages. If a line is
        // unmistakably a source assignment but the generic declaration regex could not bind its
        // LHS (for example an indexed C# request expression), recover the final LHS identifier.
        var equals = text.IndexOf('=');
        var lineSource = SourceKind(text);
        if (equals > 0 && lineSource.HasValue)
        {
            var lhs = Regex.Match(text[..equals], @"(?<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*$");
            if (lhs.Success)
            {
                var name = NormalizeExpression(lhs.Groups["name"].Value);
                _tainted[name] = lineSource.Value;
                if (_currentFunction is null)
                    _globalTainted[name] = lineSource.Value;
            }
        }

        EmitFunctionCallFlows(text, line, results);
        EmitIfTainted(text, line, SqlSinks, "SRC-FLOW-111", results, IsSqlSanitized(text));
        EmitIfTainted(text, line, CommandSinks, "SRC-FLOW-112", results, IsCommandSanitized(text));
        EmitIfTainted(text, line, PathSinks, "SRC-FLOW-113", results, IsPathSanitized(text));
        EmitIfTainted(text, line, UrlSinks, "SRC-FLOW-114", results, IsUrlSanitized(text));
        EmitIfTainted(text, line, RedirectSinks, "SRC-FLOW-115", results, false);
        EmitIfTainted(text, line, EvalSinks, "SRC-FLOW-116", results, false);
        EmitIfTainted(text, line, DeserializeSinks, "SRC-FLOW-117", results, IsDeserializeSanitized(text));
        EmitIfTainted(text, line, TemplateSinks, "SRC-FLOW-118", results, false);
        EmitIfTainted(text, line, LdapSinks, "SRC-FLOW-119", results, IsLdapSanitized(text));
        EmitIfTainted(text, line, HtmlSinks, "SRC-FLOW-120", results, IsHtmlSanitized(text));
        EmitIfTainted(text, line, HeaderSinks, "SRC-FLOW-121", results, IsHeaderSanitized(text));
        EmitIfTainted(text, line, NoSqlSinks, "SRC-FLOW-122", results, IsNoSqlSanitized(text));
        EmitIfTainted(text, line, RegexSinks, "SRC-FLOW-123", results, IsRegexSanitized(text));
        EmitIfTainted(text, line, XPathSinks, "SRC-FLOW-124", results, IsXPathSanitized(text));
        EmitIfTainted(text, line, XxeSinks, "SRC-FLOW-125", results, IsXxeSanitized(text));
        EmitIfTainted(text, line, LogSinks, "SRC-FLOW-126", results, IsLogSanitized(text));
        EmitIfTainted(text, line, CsvSinks, "SRC-FLOW-127", results, IsCsvSanitized(text));
        EmitIfTainted(text, line, ExpressionSinks, "SRC-FLOW-128", results, IsExpressionSanitized(text));
        EmitIfTainted(text, line, GraphQlSinks, "SRC-FLOW-129", results, IsGraphQlSanitized(text));
        EmitIfTainted(text, line, DynamicLoadingSinks, "SRC-FLOW-130", results, IsDynamicLoadingSanitized(text));

        if (_currentFunction is not null && _currentFunctionUsesBraces && _functionBraceDepth <= 0)
            FinishFunction();
        return results;
    }

    private void EmitIfTainted(string text, FileLine line, Regex[] sinks, string ruleId, ICollection<SourceRuleMatch> results, bool sanitized)
    {
        if (!sinks.Any(r => r.IsMatch(text))) return;
        // Some APIs have a line-level safety invariant (for example subprocess(..., shell=false)
        // or a canonicalized path). Preserve those established boundaries; expression-level
        // sanitizers are handled below so a safe first argument cannot hide a dangerous sibling.
        if (sanitized) return;
        var code = CodeWithoutStrings(text);
        // Sanitization is an expression property, not a line property. A line such as
        // execute(sqlEscape(id), attackerControlledOptions) must still report the second tainted
        // argument. Strip only sanitizer calls belonging to this sink before testing each argument.
        var relevant = GetRelevantSinkExpressions(code, ruleId)
            .Select(expression => StripSanitizedSubexpressions(expression, ruleId))
            .ToArray();
        var tainted = relevant.SelectMany(expression => _tainted
            .Where(pair => ExpressionContainsTaint(expression, pair.Key)
                && !IsSanitizedForRule(pair.Key, ruleId)))
            .Select(pair => pair.Key)
            .FirstOrDefault();
        if (tainted is null && relevant.Any(expression => SourceKind(expression).HasValue))
            tainted = "direct-input";
        if (tainted is null && _currentFunction is not null)
        {
            for (var i = 0; i < _currentParameters.Count; i++)
            {
                if (relevant.Any(expression => ParameterIndices(expression).Contains(i)))
                {
                    tainted = _currentParameters[i];
                    if (!_currentSinkParameters.TryGetValue(i, out var ruleIds))
                        _currentSinkParameters[i] = ruleIds = new HashSet<string>(StringComparer.Ordinal);
                    ruleIds.Add(ruleId);
                    break;
                }
            }
        }
        if (tainted is null) return;

        var rule = SourceFlowRules.All.First(r => r.RuleId == ruleId);
        results.Add(new SourceRuleMatch(rule, line.Number, line.Text, tainted));
    }

    private static IEnumerable<string> GetRelevantSinkExpressions(string code, string ruleId)
    {
        if (ruleId == "SRC-FLOW-120")
        {
            var equals = code.IndexOf('=');
            if (equals >= 0)
            {
                yield return code[(equals + 1)..];
                yield break;
            }
        }

        if (ruleId == "SRC-FLOW-121")
        {
            var colon = code.IndexOf(':');
            if (colon >= 0 && code.IndexOf("Location", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                yield return code[(colon + 1)..];
                yield break;
            }
        }

        var open = code.IndexOf('(');
        if (open < 0)
        {
            yield return code;
            yield break;
        }

        var args = SplitArguments(code[(open + 1)..].TrimEnd().TrimEnd(';'));
        if (ruleId == "SRC-FLOW-111")
        {
            var callee = code[..open].Trim();
            var name = callee[(callee.LastIndexOfAny(new[] { ' ', '\t', '.', ':' }) + 1)..];
            if (name.Equals("sqlite3_exec", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("mysql_query", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("PQexec", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("SQLExecDirect", StringComparison.OrdinalIgnoreCase))
            {
                if (args.Count > 1)
                    yield return args[1];
                yield break;
            }
        }
        if (ruleId == "SRC-FLOW-112")
        {
            // Command APIs commonly accept the executable followed by one or more attacker-
            // controlled arguments. Unlike SQL/URL sinks, any argument can be the dangerous one.
            foreach (var argument in args)
                yield return argument;
            // Rust's std::process::Command is commonly constructed as Command::new(...).arg(...).
            // The sink is the complete builder chain, so inspect every chained argument rather
            // than only the first constructor argument.
            foreach (Match chained in Regex.Matches(code, @"\.arg\s*\(([^)]*)\)", RegexOptions.CultureInvariant))
                yield return chained.Groups[1].Value;
            yield break;
        }
        if (ruleId == "SRC-FLOW-116")
        {
            var callee = code[..open].Trim();
            var name = callee[(callee.LastIndexOfAny(new[] { ' ', '\t', '.', ':' }) + 1)..];
            if (name.Equals("luaL_dostring", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("luaL_loadstring", StringComparison.OrdinalIgnoreCase))
            {
                if (name.Equals("luaL_dostring", StringComparison.OrdinalIgnoreCase) && args.Count > 1)
                    yield return args[1];
                else if (args.Count > 0)
                    yield return args[^1];
                yield break;
            }
        }
        var index = ruleId == "SRC-FLOW-121" ? 1 : 0;
        if (args.Count > index)
        {
            if (ruleId is "SRC-FLOW-125" or "SRC-FLOW-126" or "SRC-FLOW-127" or "SRC-FLOW-128" or "SRC-FLOW-129" or "SRC-FLOW-130")
            {
                foreach (var argument in args)
                    yield return argument;
            }
            else
                yield return args[index];
        }
    }

    /// <summary>
    /// Removes complete sink-specific sanitizer calls from an expression while preserving other
    /// arguments. A small balanced-parenthesis scanner is used instead of a regex so nested calls
    /// such as sqlEscape(normalize(req.query.id)) are handled without making the sink regex itself
    /// vulnerable to catastrophic backtracking.
    /// </summary>
    private static string StripSanitizedSubexpressions(string expression, string ruleId)
    {
        var code = expression.ToCharArray();
        var source = expression;
        var names = SanitizerNames(ruleId);
        if (names.Count == 0) return source;

        foreach (Match match in Regex.Matches(source, @"\b[A-Za-z_$][A-Za-z0-9_$.]*\s*\(", RegexOptions.CultureInvariant))
        {
            var functionName = match.Value[..match.Value.IndexOf('(')].Trim();
            if (!names.Contains(functionName, StringComparer.OrdinalIgnoreCase))
                continue;

            var open = match.Index + match.Value.IndexOf('(');
            var close = FindMatchingParenthesis(source, open);
            if (close < 0) continue;
            for (var i = match.Index; i <= close && i < code.Length; i++)
                code[i] = ' ';
        }
        return new string(code);
    }

    private static int FindMatchingParenthesis(string text, int open)
    {
        var depth = 0;
        var quote = '\0';
        var escaped = false;
        for (var i = open; i < text.Length; i++)
        {
            var c = text[i];
            if (quote != '\0')
            {
                if (escaped) { escaped = false; continue; }
                if (c == '\\') { escaped = true; continue; }
                if (c == quote) quote = '\0';
                continue;
            }
            if (c is '\'' or '"' or '`') { quote = c; continue; }
            if (c == '(') depth++;
            else if (c == ')' && --depth == 0) return i;
        }
        return -1;
    }

    private static IReadOnlyList<string> SanitizerNames(string ruleId) => ruleId switch
    {
        "SRC-FLOW-111" => ["parameterize", "parameterized", "bindValue", "bindParam", "escapeSql", "sqlEscape"],
        "SRC-FLOW-112" => ["escapeShell", "shellEscape", "allowlistCommand", "allowlistedCommand"],
        "SRC-FLOW-113" => ["basename", "realpath", "resolve", "canonicalize", "canonicalise", "safePath", "safeFileName"],
        "SRC-FLOW-114" => ["allowlistedUrl", "allowlistedHost", "validateUrl", "validateHost", "safeUrl"],
        "SRC-FLOW-115" => ["allowlistedRedirect", "validateRedirect", "safeRedirect"],
        "SRC-FLOW-117" => ["safeLoad", "allowlistedType", "validatePayload"],
        "SRC-FLOW-118" => ["sanitizeHtml", "sanitizeTemplate", "escapeHtml", "safeTemplate"],
        "SRC-FLOW-119" => ["escapeFilter", "escapeLdap", "ldapFilterEscape"],
        "SRC-FLOW-120" => ["sanitizeHtml", "DOMPurify.sanitize", "htmlEncode", "escapeHtml"],
        "SRC-FLOW-121" => ["validateHeader", "sanitizeHeader", "headerValue"],
        "SRC-FLOW-122" => ["sanitizeQuery", "typedFilter", "allowlistedFields", "allowedOperators"],
        "SRC-FLOW-123" => ["validatePattern", "allowlistedPattern", "sanitizeRegex"],
        "SRC-FLOW-124" => ["parameterizedXPath", "XPathVariable", "escapeXPath", "validateXPath", "allowlistedXPath"],
        "SRC-FLOW-125" => ["disableExternalEntities", "secureXml", "safeXml", "noDtd", "setFeatureSecure"],
        "SRC-FLOW-126" => ["sanitizeLog", "escapeLog", "structuredLog", "logSafe", "encodeForLog"],
        "SRC-FLOW-127" => ["sanitizeCsv", "escapeCsv", "csvSafe", "neutralizeFormula", "quoteCsv"],
        "SRC-FLOW-128" => ["allowlistedExpression", "safeExpression", "parseLiteral", "expressionAllowlist"],
        "SRC-FLOW-129" => ["GraphQLVariables", "buildParameterizedQuery", "parseGraphQL", "allowlistedOperation"],
        "SRC-FLOW-130" => ["allowlistedModule", "allowlistedClass", "safeImport", "trustedModule", "validateModuleName"],
        _ => []
    };

    private static bool ExpressionContainsTaint(string expression, string taintedName)
    {
        // GetRelevantSinkExpressions already receives a string-stripped code view. Keep that view
        // intact so an expression selected from inside a quoted argument is not stripped again.
        var code = expression;
        if (taintedName.Contains('.', StringComparison.Ordinal))
            return Regex.IsMatch(code, $@"(?<![A-Za-z0-9_$]){Regex.Escape(taintedName)}(?![A-Za-z0-9_$])");
        return Identifier.Matches(code).Any(m => m.Value == taintedName);
    }

    private bool IsSanitizedForRule(string variable, string ruleId) =>
        _sanitizedVariables.TryGetValue(variable, out var kinds) &&
        kinds.Contains(ruleId, StringComparer.Ordinal);

    private static HashSet<string> SanitizerKinds(string expression)
    {
        var code = CodeWithoutStrings(expression);
        var kinds = new HashSet<string>(StringComparer.Ordinal);

        if (Regex.IsMatch(code, @"\b(?:parameteri[sz]e|bind(?:Value|Param)|escapeSql|sqlEscape)\w*\s*\(", RegexOptions.IgnoreCase))
            kinds.Add("SRC-FLOW-111");
        if (Regex.IsMatch(code, @"\b(?:escapeShell|shellEscape|allowlist(?:Command|edCommand))\w*\s*\(", RegexOptions.IgnoreCase))
            kinds.Add("SRC-FLOW-112");
        if (Regex.IsMatch(code, @"\b(?:basename|realpath|resolve|canonicalize|canonicalise|safePath|safeFileName)\w*\s*\(", RegexOptions.IgnoreCase))
            kinds.Add("SRC-FLOW-113");
        if (Regex.IsMatch(code, @"\b(?:allowlist(?:ed)?Url|allowlist(?:ed)?Host|validateUrl|validateHost|safeUrl)\w*\s*\(", RegexOptions.IgnoreCase))
            kinds.Add("SRC-FLOW-114");
        if (Regex.IsMatch(code, @"\b(?:allowlist(?:ed)?Redirect|validateRedirect|safeRedirect)\w*\s*\(", RegexOptions.IgnoreCase))
            kinds.Add("SRC-FLOW-115");
        if (Regex.IsMatch(code, @"\b(?:safeLoad|allowlist(?:ed)?Type|validatePayload)\w*\s*\(", RegexOptions.IgnoreCase))
            kinds.Add("SRC-FLOW-117");
        if (Regex.IsMatch(code, @"\b(?:sanitize(?:Html|Template)?|escapeHtml|safeTemplate)\w*\s*\(", RegexOptions.IgnoreCase))
            kinds.Add("SRC-FLOW-118");
        if (Regex.IsMatch(code, @"\b(?:escapeFilter|escapeLdap|ldapFilterEscape)\w*\s*\(", RegexOptions.IgnoreCase))
            kinds.Add("SRC-FLOW-119");
        if (Regex.IsMatch(code, @"\b(?:sanitizeHtml|DOMPurify\.sanitize|htmlEncode|escapeHtml)\w*\s*\(", RegexOptions.IgnoreCase))
            kinds.Add("SRC-FLOW-120");
        if (Regex.IsMatch(code, @"\b(?:validateHeader|sanitizeHeader|headerValue)\w*\s*\(", RegexOptions.IgnoreCase))
            kinds.Add("SRC-FLOW-121");
        if (Regex.IsMatch(code, @"\b(?:sanitizeQuery|typedFilter|allowlistedFields|allowedOperators)\w*\s*\(", RegexOptions.IgnoreCase))
            kinds.Add("SRC-FLOW-122");
        if (Regex.IsMatch(code, @"\b(?:validatePattern|allowlistedPattern|sanitizeRegex)\w*\s*\(", RegexOptions.IgnoreCase))
            kinds.Add("SRC-FLOW-123");
        if (Regex.IsMatch(code, @"\b(?:parameterizedXPath|XPathVariable|escapeXPath|validateXPath|allowlistedXPath)\w*\s*\(", RegexOptions.IgnoreCase))
            kinds.Add("SRC-FLOW-124");
        if (Regex.IsMatch(code, @"\b(?:disableExternalEntities|secureXml|safeXml|noDtd|setFeatureSecure|resolveEntities\s*\(\s*false)\b", RegexOptions.IgnoreCase))
            kinds.Add("SRC-FLOW-125");
        if (Regex.IsMatch(code, @"\b(?:sanitizeLog|escapeLog|structuredLog|logSafe|encodeForLog)\w*\s*\(", RegexOptions.IgnoreCase))
            kinds.Add("SRC-FLOW-126");
        if (Regex.IsMatch(code, @"\b(?:sanitizeCsv|escapeCsv|csvSafe|neutralizeFormula|quoteCsv)\w*\s*\(", RegexOptions.IgnoreCase))
            kinds.Add("SRC-FLOW-127");
        if (Regex.IsMatch(code, @"\b(?:allowlistedExpression|safeExpression|parseLiteral|expressionAllowlist)\w*\s*\(", RegexOptions.IgnoreCase))
            kinds.Add("SRC-FLOW-128");
        if (Regex.IsMatch(code, @"\b(?:GraphQLVariables|buildParameterizedQuery|parseGraphQL|allowlistedOperation)\w*\s*\(", RegexOptions.IgnoreCase))
            kinds.Add("SRC-FLOW-129");
        if (Regex.IsMatch(code, @"\b(?:allowlistedModule|allowlistedClass|safeImport|trustedModule|validateModuleName)\w*\s*\(", RegexOptions.IgnoreCase))
            kinds.Add("SRC-FLOW-130");

        return kinds;
    }

    private SourceTaintKind? SourceKind(string expression)
    {
        if (RequestSources.Any(r => r.IsMatch(expression)) ||
            Regex.IsMatch(expression, @"\b(?:Request|request|req)\s*(?:\.\s*(?:Query|Form|Headers|Cookies|Path|RouteValues|query|body|params|form|args|values|headers|cookies)|\[)", RegexOptions.IgnoreCase))
            return SourceTaintKind.Request;
        if (EnvironmentSources.Any(r => r.IsMatch(expression))) return SourceTaintKind.Environment;
        if (UserInputSources.Any(r => r.IsMatch(expression))) return SourceTaintKind.UserInput;
        return null;
    }

    private bool TryTaintedFunctionCall(string expression, out SourceTaintKind kind, string? assignedVariable = null, FileLine line = default)
    {
        kind = default;
        var call = FunctionCallAssignment.Match(expression);
        if (!call.Success)
            call = FunctionCall.Match(expression);
        if (!call.Success) return false;

        var functionName = call.Groups["call"].Success ? call.Groups["call"].Value : call.Groups["fn"].Value;
        if (!TryResolveFunction(functionName, out var summary))
        {
            _pendingCalls.Add(new PendingCall(functionName, SplitArguments(call.Groups["args"].Value), assignedVariable, line));
            return false;
        }

        if (summary.DirectReturn.HasValue)
        {
            kind = summary.DirectReturn.Value;
            return true;
        }

        var args = SplitArguments(call.Groups["args"].Value);
        foreach (var index in summary.ReturnParameters)
        {
            if (index < args.Count && TryGetTaint(args[index], out kind))
                return true;
        }

        return false;
    }

    private void TrackFunctionContext(string code)
    {
        var declaration = FunctionDeclaration.Match(code);
        var arrow = ArrowFunctionDeclaration.Match(code);

        if (RequestHandlerAnnotations.IsMatch(code) && !declaration.Success && !arrow.Success)
            _pendingRequestHandlerAnnotation = code;

        // Python is indentation-delimited. A top-level statement ends the previous function
        // before that statement is analyzed, otherwise its locals would incorrectly leak into
        // subsequent top-level code.
        if (_language == SourceLanguage.Py && _currentFunction is not null && !declaration.Success && !arrow.Success)
        {
            var raw = code.TrimStart();
            var indent = code.Length - raw.Length;
            if (raw.Length > 0 && indent <= _currentFunctionIndent)
                FinishFunction();
        }

        if (declaration.Success || arrow.Success)
        {
            if (_currentFunction is not null)
                FinishFunction();
            var parameterText = declaration.Success ? declaration.Groups["params"].Value : arrow.Groups["params"].Value;
            if (arrow.Success && arrow.Groups["single"].Success)
                parameterText = arrow.Groups["single"].Value;
            _currentParameters = ParseParameters(parameterText);
            _currentReturnParameters.Clear();
            _currentSinkParameters.Clear();
            _currentDirectReturn = null;
            _currentFunction = (declaration.Success ? declaration.Groups["name"] : arrow.Groups["name"]).Value;
            _functionBraceDepth = 0;
            _currentFunctionUsesBraces = code.Contains('{');
            var raw = code.TrimStart();
            _currentFunctionIndent = code.Length - raw.Length;
            _tainted = new Dictionary<string, SourceTaintKind>(_globalTainted, StringComparer.Ordinal);
            _sanitizedVariables.Clear();

            // Promote only explicitly bound handler parameters or parameters whose types prove
            // framework ownership. Tainting every parameter would manufacture request-to-sink
            // edges throughout ordinary application code.
            var parameterDeclaration = declaration.Success ? declaration.Groups["params"].Value : arrow.Groups["params"].Value;
            var explicitlyBound = RequestBoundParameterMarkers.IsMatch(parameterDeclaration)
                || RequestParameterTypes.IsMatch(parameterDeclaration)
                // FastAPI/Flask-style route decorators make ordinary scalar handler parameters
                // request-controlled; dependency injection markers remain excluded below.
                || (_pendingRequestHandlerAnnotation is not null && _language == SourceLanguage.Py);
            if (explicitlyBound)
            {
                foreach (var parameter in _currentParameters)
                {
                    if (parameter.Length > 0 && !Regex.IsMatch(
                        parameterDeclaration,
                        $@"\b(?:Depends|Inject|Provide)\s*\([^)]*\b{Regex.Escape(parameter)}\b",
                        RegexOptions.IgnoreCase))
                        _tainted[parameter] = SourceTaintKind.Request;
                }
            }

            _pendingRequestHandlerAnnotation = null;

        }

        if (_currentFunction is null) return;
        foreach (var c in code)
        {
            if (c == '{') _functionBraceDepth++;
            else if (c == '}') _functionBraceDepth--;
        }

        // Python/brace-less functions are finalized by the next declaration. Brace-based
        // functions are finalized after their closing brace has been analyzed.
    }

    private void TrackModuleImports(string text)
    {
        foreach (Match import in JavaScriptNamespaceImport.Matches(text))
            AddFunctionAlias(import.Groups["local"].Value,
                new ImportAlias(import.Groups["specifier"].Value, "*"));

        foreach (Match import in JavaScriptImport.Matches(text))
        {
            var specifier = Regex.Match(import.Value, @"from\s*['""]([^'""]+)['""]", RegexOptions.IgnoreCase).Groups[1].Value;
            foreach (var binding in import.Groups["bindings"].Value.Split(',', StringSplitOptions.RemoveEmptyEntries))
            {
                var parts = binding.Trim().Split(new[] { " as " }, 2, StringSplitOptions.TrimEntries);
                var imported = parts[0].Trim();
                var local = parts.Length == 2 ? parts[1].Trim() : imported;
                if (Identifier.IsMatch(imported) && Identifier.IsMatch(local))
                    AddFunctionAlias(local, new ImportAlias(specifier, imported));
            }
        }

        foreach (Match import in CommonJsDestructuringImport.Matches(text))
        {
            var specifier = import.Groups["specifier"].Value;
            foreach (var binding in import.Groups["bindings"].Value.Split(',', StringSplitOptions.RemoveEmptyEntries))
            {
                var parts = binding.Trim().Split(':', 2, StringSplitOptions.TrimEntries);
                var imported = parts[0].Trim();
                var local = parts.Length == 2 ? parts[1].Trim() : imported;
                if (Identifier.IsMatch(imported) && Identifier.IsMatch(local))
                    AddFunctionAlias(local, new ImportAlias(specifier, imported));
            }
        }

        foreach (Match import in CommonJsNamespaceImport.Matches(text))
            AddFunctionAlias(import.Groups["local"].Value,
                new ImportAlias(import.Groups["specifier"].Value, "*"));

        foreach (Match import in PythonImport.Matches(text))
        {
            var module = Regex.Match(import.Value, @"\bfrom\s+([A-Za-z_][A-Za-z0-9_.]*)", RegexOptions.IgnoreCase).Groups[1].Value;
            foreach (var binding in import.Groups["bindings"].Value.Split(',', StringSplitOptions.RemoveEmptyEntries))
            {
                var parts = Regex.Split(binding.Trim(), @"\s+as\s+", RegexOptions.IgnoreCase);
                var imported = parts[0].Trim();
                var local = parts.Length == 2 ? parts[1].Trim() : imported;
                if (Identifier.IsMatch(imported) && Identifier.IsMatch(local))
                    AddFunctionAlias(local, new ImportAlias(module.Replace('.', '/'), imported));
            }
        }

        foreach (Match import in PythonNamespaceImport.Matches(text))
        {
            var module = import.Groups["module"].Value;
            var local = import.Groups["local"].Success ? import.Groups["local"].Value : module.Split('.').Last();
            AddFunctionAlias(local, new ImportAlias(module.Replace('.', '/'), "*"));
        }
    }

    private void AddFunctionAlias(string localName, ImportAlias alias)
    {
        if (!_functionAliases.TryGetValue(localName, out var existing))
        {
            _functionAliases[localName] = alias;
            return;
        }

        if (existing is null || !existing.Equals(alias))
            _functionAliases[localName] = null;
    }

    private void FinishFunction()
    {
        if (_currentFunction is null) return;

        var summary = new FunctionSummary(
            _currentDirectReturn,
            _currentReturnParameters.ToArray(),
            _currentSinkParameters.ToDictionary(
                pair => pair.Key,
                pair => (IReadOnlySet<string>)pair.Value.ToHashSet(StringComparer.Ordinal)));
        if (_ambiguousLocalFunctions.Contains(_currentFunction))
        {
            // Once a same-name declaration has produced a different summary, resolving by name
            // alone is unsafe. Keep the ambiguity explicit rather than letting source order choose
            // an overload and manufacture a flow edge.
        }
        else if (_localFunctionSummaries.TryGetValue(_currentFunction, out var existing) && !Equals(existing, summary))
        {
            _ambiguousLocalFunctions.Add(_currentFunction);
            _localFunctionSummaries.Remove(_currentFunction);
            _taintedFunctions.Remove(_currentFunction);
        }
        else
        {
            _taintedFunctions[_currentFunction] = summary;
            _localFunctionSummaries[_currentFunction] = summary;
        }

        _currentFunction = null;
        _currentParameters = [];
        _currentReturnParameters.Clear();
        _currentSinkParameters.Clear();
        _currentDirectReturn = null;
        _functionBraceDepth = 0;
        _currentFunctionIndent = -1;
        _currentFunctionUsesBraces = false;
        _tainted = new Dictionary<string, SourceTaintKind>(_globalTainted, StringComparer.Ordinal);
        _sanitizedVariables.Clear();
    }

    private void EmitFunctionCallFlows(string text, FileLine line, ICollection<SourceRuleMatch> results)
    {
        foreach (Match call in FunctionCall.Matches(CodeWithoutStrings(text)))
        {
            var functionName = call.Groups["fn"].Value;
            if (!TryResolveFunction(functionName, out var summary))
                continue;

            var args = SplitArguments(call.Groups["args"].Value);
            foreach (var pair in summary.SinkParameters)
            {
                if (pair.Key >= args.Count)
                    continue;
                if (_currentFunction is not null)
                {
                    foreach (var callerParameter in ParameterIndices(args[pair.Key]))
                    {
                        if (!_currentSinkParameters.TryGetValue(callerParameter, out var ruleIds))
                            _currentSinkParameters[callerParameter] = ruleIds = new HashSet<string>(StringComparer.Ordinal);
                        ruleIds.UnionWith(pair.Value);
                    }
                }
                if (!TryGetTaint(args[pair.Key], out _))
                    continue;

                // The callee's body is the actual sink; report at the call site because this
                // lightweight engine does not have a cross-file source location graph.
                foreach (var ruleId in pair.Value)
                {
                    if (!results.Any(m => m.Rule.RuleId == ruleId && m.LineNumber == line.Number))
                    {
                        var rule = SourceFlowRules.All.First(r => r.RuleId == ruleId);
                        results.Add(new SourceRuleMatch(rule, line.Number, line.Text, args[pair.Key]));
                    }
                }
                break;
            }
        }
    }

    private bool TryGetTaint(string expression, out SourceTaintKind kind)
    {
        var normalized = NormalizeExpression(expression);
        if (_tainted.TryGetValue(normalized, out kind))
            return true;

        var source = SourceKind(expression);
        if (source.HasValue) { kind = source.Value; return true; }
        if (ContainsTaintedIdentifier(expression)) { kind = FirstTaint(expression); return true; }
        kind = default;
        return false;
    }

    private SourceTaintKind? ResolveCallReturnTaint(FunctionSummary summary, IReadOnlyList<string> args)
    {
        if (summary.DirectReturn.HasValue) return summary.DirectReturn.Value;
        foreach (var index in summary.ReturnParameters)
            if (index < args.Count && TryGetTaint(args[index], out var kind)) return kind;
        return null;
    }

    private bool TryResolveReturnCall(string expression, out SourceTaintKind? directTaint, out IReadOnlyList<int> parameterIndices)
    {
        directTaint = null;
        parameterIndices = [];
        var call = FunctionCall.Match(CodeWithoutStrings(expression));
        if (!call.Success || !TryResolveFunction(call.Groups["fn"].Value, out var summary))
            return false;

        var args = SplitArguments(call.Groups["args"].Value);
        if (summary.DirectReturn.HasValue)
        {
            directTaint = summary.DirectReturn.Value;
            return true;
        }

        var mapped = new List<int>();
        foreach (var calleeParameter in summary.ReturnParameters)
        {
            if (calleeParameter >= args.Count)
                continue;
            mapped.AddRange(ParameterIndices(args[calleeParameter]));
        }
        parameterIndices = mapped.Distinct().ToArray();
        return parameterIndices.Count > 0;
    }

    private void ResolvePendingAssignments()
    {
        foreach (var call in _pendingCalls)
        {
            if (call.AssignedVariable is null || !TryResolveFunction(call.FunctionName, out var summary))
                continue;
            if (ResolveCallReturnTaint(summary, call.Arguments) is { } taint)
                _tainted[NormalizeExpression(call.AssignedVariable)] = taint;
        }
    }

    private IEnumerable<int> ParameterIndices(string expression)
    {
        var ids = Identifier.Matches(CodeWithoutStrings(expression)).Select(m => m.Value).ToHashSet(StringComparer.Ordinal);
        for (var i = 0; i < _currentParameters.Count; i++)
            if (ids.Contains(_currentParameters[i])) yield return i;
    }

    private static List<string> ParseParameters(string parameters) =>
        parameters.Split(',', StringSplitOptions.RemoveEmptyEntries)
            .Select(static parameter =>
            {
                var value = parameter.Trim();
                var colon = value.IndexOf(':');
                if (colon > 0)
                    return Regex.Match(value[..colon], @"[A-Za-z_$][A-Za-z0-9_$]*\s*$").Value;
                if (Regex.IsMatch(value, @"^[A-Za-z_$][A-Za-z0-9_$]*\s+\*"))
                    return Regex.Match(value, @"^[A-Za-z_$][A-Za-z0-9_$]*").Value;
                return Regex.Match(value, @"[A-Za-z_$][A-Za-z0-9_$]*\s*$").Value;
            })
            .Where(n => n.Length > 0).ToList();

    private static List<string> SplitArguments(string text)
    {
        var result = new List<string>();
        var start = 0;
        var depth = 0;
        var quote = '\0';
        var escaped = false;
        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            if (quote != '\0')
            {
                if (escaped) { escaped = false; continue; }
                if (c == '\\') { escaped = true; continue; }
                if (c == quote) quote = '\0';
                continue;
            }
            if (c is '\'' or '"' or '`') { quote = c; continue; }
            if (c is '(' or '[' or '{') { depth++; continue; }
            if (c is ')' or ']' or '}') { if (depth > 0) depth--; continue; }
            if (c == ',' && depth == 0)
            {
                result.Add(text[start..i].Trim());
                start = i + 1;
            }
        }
        if (start < text.Length)
            result.Add(text[start..].Trim());
        return result;
    }

    private bool TryResolveFunction(string functionName, out FunctionSummary summary)
    {
        summary = null!;
        if (_functionAliases.TryGetValue(functionName, out var alias))
        {
            if (alias is not null && _catalog is not null && _modulePath is not null &&
                _catalog.TryResolveImport(_modulePath, alias.Specifier, alias.ImportedName, out summary!))
                return true;

            // An explicit import that cannot be resolved locally is intentionally fail-closed.
            // Falling back to a same-named function from an unrelated module can manufacture a
            // source-flow edge that does not exist in the program.
            summary = null!;
            return false;
        }

        // Namespace imports (ES modules and Python-style module imports) resolve the member name
        // against the imported module rather than against the repository-wide short-name index.
        var separator = functionName.IndexOf('.');
        if (separator > 0 && _functionAliases.TryGetValue(functionName[..separator], out var namespaceAlias) &&
            namespaceAlias is not null && namespaceAlias.ImportedName == "*" &&
            _catalog is not null && _modulePath is not null &&
            _catalog.TryResolveImport(_modulePath, namespaceAlias.Specifier, functionName[(separator + 1)..], out summary!))
            return true;

        if (!_ambiguousLocalFunctions.Contains(functionName) && _taintedFunctions.TryGetValue(functionName, out summary!))
            return true;

        var shortName = functionName[(functionName.LastIndexOf('.') + 1)..];
        if (shortName.Equals(functionName, StringComparison.OrdinalIgnoreCase))
            return false;

        return !_ambiguousLocalFunctions.Contains(shortName) && _taintedFunctions.TryGetValue(shortName, out summary!);
    }

    private static string NormalizeExpression(string expression) =>
        Regex.Replace(CodeWithoutStrings(expression).Trim(), @"\s+", string.Empty);
    private bool ContainsTaintedIdentifier(string expression)
    {
        var code = CodeWithoutStrings(expression);
        if (_tainted.Keys.Any(name => Identifier.IsMatch(name) && Identifier.Matches(code).Any(m => m.Value == name)))
            return true;

        return _tainted.Keys.Any(name => name.Contains('.', StringComparison.Ordinal)
            && Regex.IsMatch(code, $@"(?<![A-Za-z0-9_$]){Regex.Escape(name)}(?![A-Za-z0-9_$])"));
    }

    private bool ContainsAmbiguousFunctionCall(string expression)
    {
        foreach (Match call in FunctionCall.Matches(CodeWithoutStrings(expression)))
        {
            var name = call.Groups["fn"].Value;
            var shortName = name[(name.LastIndexOf('.') + 1)..];
            if (_ambiguousLocalFunctions.Contains(name) || _ambiguousLocalFunctions.Contains(shortName))
                return true;
        }
        return false;
    }

    private SourceTaintKind FirstTaint(string expression)
    {
        var code = CodeWithoutStrings(expression);
        var identifierTaint = _tainted.FirstOrDefault(kvp => Identifier.IsMatch(kvp.Key) &&
            Identifier.Matches(code).Any(m => m.Value == kvp.Key));
        if (!identifierTaint.Equals(default(KeyValuePair<string, SourceTaintKind>)))
            return identifierTaint.Value;

        foreach (var pair in _tainted)
            if (pair.Key.Contains('.', StringComparison.Ordinal) &&
                Regex.IsMatch(code, $@"(?<![A-Za-z0-9_$]){Regex.Escape(pair.Key)}(?![A-Za-z0-9_$])"))
                return pair.Value;

        return default;
    }

    /// <summary>Returns a code-only view so a variable name mentioned inside a string literal cannot carry taint.</summary>
    private static string CodeWithoutStrings(string text)
    {
        var chars = text.ToCharArray();
        var quote = '\0';
        var escaped = false;
        for (var i = 0; i < chars.Length; i++)
        {
            var c = chars[i];
            if (quote == '\0')
            {
                if (c is '\"' or '\'' or '`')
                {
                    chars[i] = ' ';
                    quote = c;
                }
                continue;
            }

            if (escaped)
            {
                chars[i] = ' ';
                escaped = false;
                continue;
            }

            if (c == '\\')
            {
                chars[i] = ' ';
                escaped = true;
            }
            else if (c == quote)
            {
                chars[i] = ' ';
                quote = '\0';
            }
            else
            {
                chars[i] = ' ';
            }
        }

        return new string(chars);
    }

    private static bool IsKnownSanitizerCall(string expression) =>
        Regex.IsMatch(CodeWithoutStrings(expression), @"\b(?:sqlEscape|escapeSql|parameterize|bind(?:Value|Param)|safePath|safeUrl|safeRedirect|safeLoad|sanitizeHtml|escapeHtml|escapeFilter|escapeLdap|validateHeader|sanitizeQuery)\s*\(", RegexOptions.IgnoreCase);

    private static bool IsSqlSanitized(string text)
    {
        var code = CodeWithoutStrings(text);
        return Regex.IsMatch(code, @"\b(?:SqlParameter|PreparedStatement|prepare\s*\(|parameteri[sz]ed|bind(?:Value|Param))\b", RegexOptions.IgnoreCase);
    }

    private static bool IsCommandSanitized(string text)
    {
        var code = CodeWithoutStrings(text);
        return (Regex.IsMatch(code, @"\b(?:ArgumentList|ProcessStartInfo|execve|execvp)\b", RegexOptions.IgnoreCase)
                || Regex.IsMatch(code, @"\bshell\s*=\s*false\b", RegexOptions.IgnoreCase))
               && !Regex.IsMatch(code, @"\b(?:shell|bash|sh)\s*[:=]\s*true\b", RegexOptions.IgnoreCase);
    }

    private static bool IsPathSanitized(string text)
    {
        var code = CodeWithoutStrings(text);
        return Regex.IsMatch(code, @"\b(?:GetFileName|basename|realpath|resolve|canonicalize|Path\.GetFullPath)\s*\(", RegexOptions.IgnoreCase);
    }

    private static bool IsUrlSanitized(string text) => Regex.IsMatch(CodeWithoutStrings(text), @"\b(?:Uri\.CheckHostName|IsAllowedHost|AllowlistedHost|AllowedHosts|UrlAllowlist|allowlist(?:ed)?Url|Uri\.TryCreate)\b", RegexOptions.IgnoreCase);
    private static bool IsDeserializeSanitized(string text) => Regex.IsMatch(CodeWithoutStrings(text), @"\b(?:allowedTypes|TypeNameHandling\.None|safe_load|SafeLoad|allowlist)\b", RegexOptions.IgnoreCase);
    private static bool IsLdapSanitized(string text) => Regex.IsMatch(CodeWithoutStrings(text), @"\b(?:EscapeFilter|EscapeFilterComponent|LdapFilterEscape|escape_filter_chars|RFC4515)\s*\(", RegexOptions.IgnoreCase);
    private static bool IsHtmlSanitized(string text) => Regex.IsMatch(CodeWithoutStrings(text), @"\b(?:DOMPurify\.sanitize|sanitizeHtml|htmlspecialchars|HtmlEncode|HtmlEncoder\.Default\.Encode|escapeHtml)\s*\(", RegexOptions.IgnoreCase);
    private static bool IsHeaderSanitized(string text) => Regex.IsMatch(CodeWithoutStrings(text), @"\b(?:validateHeader|sanitizeHeader|HeaderValue\.TryParse|reject(?:ed)?CrLf)\b", RegexOptions.IgnoreCase);
    private static bool IsNoSqlSanitized(string text) => Regex.IsMatch(CodeWithoutStrings(text), @"\b(?:allowlistedFields|allowedOperators|sanitizeQuery|strictQuery|typedFilter)\b", RegexOptions.IgnoreCase);
    private static bool IsRegexSanitized(string text) => Regex.IsMatch(CodeWithoutStrings(text), @"\b(?:RegexOptions\.NonBacktracking|timeout|allowlistedPattern|validatePattern|sanitizeRegex)\b", RegexOptions.IgnoreCase);
    private static bool IsXPathSanitized(string text) => Regex.IsMatch(CodeWithoutStrings(text), @"\b(?:parameterizedXPath|XPathVariable|escapeXPath|validateXPath|allowlistedXPath)\b", RegexOptions.IgnoreCase);
    private static bool IsXxeSanitized(string text) => Regex.IsMatch(CodeWithoutStrings(text), @"\b(?:disableExternalEntities|noDtd|resolveEntities\s*\(\s*false|FEATURE_SECURE_PROCESSING|ACCESS_EXTERNAL_DTD)\b", RegexOptions.IgnoreCase);
    private static bool IsLogSanitized(string text) => Regex.IsMatch(CodeWithoutStrings(text), @"\b(?:sanitizeLog|escapeLog|structuredLog|logSafe|encodeForLog)\s*\(", RegexOptions.IgnoreCase);
    private static bool IsCsvSanitized(string text) => Regex.IsMatch(CodeWithoutStrings(text), @"\b(?:sanitizeCsv|escapeCsv|csvSafe|neutralizeFormula|quoteCsv)\s*\(", RegexOptions.IgnoreCase);
    private static bool IsExpressionSanitized(string text) => Regex.IsMatch(CodeWithoutStrings(text), @"\b(?:allowlistedExpression|safeExpression|parseLiteral|expressionAllowlist)\s*\(", RegexOptions.IgnoreCase);
    private static bool IsGraphQlSanitized(string text) => Regex.IsMatch(CodeWithoutStrings(text), @"\b(?:GraphQLVariables|buildParameterizedQuery|parseGraphQL|allowlistedOperation)\s*\(", RegexOptions.IgnoreCase);
    private static bool IsDynamicLoadingSanitized(string text) => Regex.IsMatch(CodeWithoutStrings(text), @"\b(?:allowlistedModule|allowlistedClass|safeImport|trustedModule|validateModuleName)\s*\(", RegexOptions.IgnoreCase);

}

/// <summary>
/// Repository-scoped function summary index. Only uniquely named functions are exposed to
/// cross-file propagation; ambiguous names fail closed instead of guessing which implementation
/// a call targets.
/// </summary>
public sealed class SourceFlowFunctionCatalog
{
    private readonly Dictionary<string, SourceFlowAnalyzer.FunctionSummary?> _functions = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, Dictionary<string, SourceFlowAnalyzer.FunctionSummary?>> _modules = new(StringComparer.OrdinalIgnoreCase);

    internal IReadOnlyDictionary<string, SourceFlowAnalyzer.FunctionSummary> UniqueFunctions =>
        _functions.Where(static pair => pair.Value is not null)
            .ToDictionary(pair => pair.Key, pair => pair.Value!, StringComparer.OrdinalIgnoreCase);

    internal void Add(IReadOnlyDictionary<string, SourceFlowAnalyzer.FunctionSummary> summaries)
    {
        foreach (var pair in summaries)
        {
            if (!_functions.TryGetValue(pair.Key, out var existing))
            {
                _functions[pair.Key] = pair.Value;
            }
            else if (existing is not null)
            {
                // Same-name declarations are ambiguous unless their summaries are structurally
                // identical. This avoids cross-file false positives from overloads or duplicates.
                _functions[pair.Key] = existing == pair.Value ? existing : null;
            }
        }
    }

    internal void Replace(IEnumerable<(string ModulePath, IReadOnlyDictionary<string, SourceFlowAnalyzer.FunctionSummary> Summaries)> summaries)
    {
        _functions.Clear();
        _modules.Clear();
        foreach (var file in summaries)
        {
            var module = new Dictionary<string, SourceFlowAnalyzer.FunctionSummary?>(StringComparer.OrdinalIgnoreCase);
            foreach (var pair in file.Summaries)
            {
                module[pair.Key] = pair.Value;
                if (!_functions.TryGetValue(pair.Key, out var existing))
                    _functions[pair.Key] = pair.Value;
                else if (existing is not null)
                    _functions[pair.Key] = existing == pair.Value ? existing : null;
            }
            _modules[NormalizeModulePath(file.ModulePath)] = module;
        }
    }

    internal bool TryResolveImport(
        string importerPath,
        string specifier,
        string functionName,
        out SourceFlowAnalyzer.FunctionSummary summary)
    {
        summary = null!;
        var candidate = ResolveModuleSpecifier(importerPath, specifier);
        foreach (var modulePath in ModuleCandidates(candidate))
        {
            if (_modules.TryGetValue(modulePath, out var module) &&
                module.TryGetValue(functionName, out var found) && found is not null)
            {
                summary = found;
                return true;
            }
        }
        return false;
    }

    internal bool StructurallyEquals(SourceFlowFunctionCatalog other)
    {
        if (_functions.Count != other._functions.Count || _modules.Count != other._modules.Count)
            return false;
        foreach (var pair in _functions)
        {
            if (!other._functions.TryGetValue(pair.Key, out var theirs) || !Equals(pair.Value, theirs))
                return false;
        }
        foreach (var module in _modules)
        {
            if (!other._modules.TryGetValue(module.Key, out var theirs) || module.Value.Count != theirs.Count)
                return false;
            foreach (var pair in module.Value)
                if (!theirs.TryGetValue(pair.Key, out var theirSummary) || !Equals(pair.Value, theirSummary))
                    return false;
        }
        return true;
    }

    private static string ResolveModuleSpecifier(string importerPath, string specifier)
    {
        if (specifier.StartsWith(".", StringComparison.Ordinal))
        {
            var baseDirectory = Path.GetDirectoryName(importerPath)?.Replace('\\', '/') ?? string.Empty;
            return NormalizeModulePath(Path.Combine(baseDirectory, specifier).Replace('\\', '/'));
        }

        return NormalizeModulePath(specifier.Replace('.', '/'));
    }

    private static IEnumerable<string> ModuleCandidates(string modulePath)
    {
        yield return modulePath;
        foreach (var extension in new[] { ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py", ".java", ".kt", ".php", ".rb" })
            yield return modulePath.EndsWith(extension, StringComparison.OrdinalIgnoreCase) ? modulePath : modulePath + extension;
        foreach (var extension in new[] { ".js", ".ts", ".py" })
            yield return modulePath.TrimEnd('/') + "/index" + extension;
    }

    private static string NormalizeModulePath(string path)
    {
        var normalized = path.Replace('\\', '/');
        var segments = new List<string>();
        foreach (var segment in normalized.Split('/', StringSplitOptions.RemoveEmptyEntries))
        {
            if (segment == ".") continue;
            if (segment == "..")
            {
                if (segments.Count > 0) segments.RemoveAt(segments.Count - 1);
                continue;
            }
            segments.Add(segment);
        }
        return string.Join("/", segments);
    }
}
