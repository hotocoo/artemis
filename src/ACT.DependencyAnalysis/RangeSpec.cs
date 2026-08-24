
using ACT.Contracts;

namespace ACT.DependencyAnalysis;

/// <summary>Three-part numeric semantic version core used for deterministic range comparison.</summary>
public readonly record struct SemanticVersion(int Major, int Minor, int Patch) : IComparable<SemanticVersion>
{
    private static readonly System.Globalization.CultureInfo Invariant = System.Globalization.CultureInfo.InvariantCulture;

    /// <summary>Parses "major.minor.patch"; shorter forms pad zeros; prerelease and build suffixes are ignored.</summary>
    public static bool TryParse(string? text, out SemanticVersion version)
    {
        version = default;
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        var core = text.Trim();
        var cut = core.IndexOfAny(['-', '+']);
        if (cut >= 0)
        {
            core = core[..cut];
        }

        var parts = core.Split('.');
        if (parts.Length is < 1 or > 3)
        {
            return false;
        }

        var numbers = new int[3];
        for (var i = 0; i < parts.Length; i++)
        {
            if (!int.TryParse(parts[i], Invariant, out var number) || number < 0)
            {
                return false;
            }

            numbers[i] = number;
        }

        version = new SemanticVersion(numbers[0], numbers[1], numbers[2]);
        return true;
    }

    /// <inheritdoc/>
    public int CompareTo(SemanticVersion other) =>
        Major != other.Major ? Major.CompareTo(other.Major)
        : Minor != other.Minor ? Minor.CompareTo(other.Minor)
        : Patch.CompareTo(other.Patch);

    /// <summary>Renders the canonical three-part form.</summary>
    public override string ToString() => string.Create(Invariant, $"{Major}.{Minor}.{Patch}");
}

/// <summary>
/// A conjunction of numeric comparison clauses such as "*", "=1.2.3", "&gt;=1,&lt;2", or "&lt;1.2.3".
/// Parsing fails closed on malformed expressions rather than guessing.
/// </summary>
public sealed record RangeSpec
{
    private readonly Clause[] _clauses;

    private RangeSpec(Clause[] clauses)
    {
        _clauses = clauses;
    }

    /// <summary>A range satisfied by every version.</summary>
    public static RangeSpec Any { get; } = new([]);

    /// <summary>Parses a comma-separated comparison expression into a spec.</summary>
    public static RangeSpec Parse(string expression)
    {
        ArgumentNullException.ThrowIfNull(expression);
        var trimmed = expression.Trim();
        if (trimmed.Length == 0 || trimmed is "*")
        {
            return Any;
        }

        var pieces = trimmed.Split(',');
        var clauses = new List<Clause>(pieces.Length);
        foreach (var piece in pieces)
        {
            var part = piece.Trim();
            if (part.Length == 0)
            {
                throw ActException.FailClosed(
                    ErrorCategory.Parser,
                    "An advisory version range contains an empty comparison clause.",
                    $"Range expression '{expression}' has an empty clause.");
            }

            char op;
            string rest;
            if (part.StartsWith(">=", StringComparison.Ordinal)) { op = 'G'; rest = part[2..]; }
            else if (part.StartsWith("<=", StringComparison.Ordinal)) { op = 'L'; rest = part[2..]; }
            else if (part.StartsWith('>')) { op = '>'; rest = part[1..]; }
            else if (part.StartsWith('<')) { op = '<'; rest = part[1..]; }
            else
            {
                op = '=';
                rest = part.TrimStart('=');
            }

            rest = rest.Trim();
            if (!SemanticVersion.TryParse(rest, out var bound))
            {
                throw ActException.FailClosed(
                    ErrorCategory.Parser,
                    "An advisory version range clause is not a valid three-part version.",
                    $"Range expression '{expression}' has malformed clause '{part}'.");
            }

            clauses.Add(new Clause(op, bound));
        }

        return new RangeSpec(clauses.ToArray());
    }

    /// <summary>Decides whether the given version falls inside this range; unparseable versions fail closed.</summary>
    public bool Satisfied(string version)
    {
        if (!SemanticVersion.TryParse(version, out var parsed))
        {
            throw ActException.FailClosed(
                ErrorCategory.Parser,
                "A dependency version could not be interpreted as a numeric release version.",
                $"Satisfied() called with malformed version '{version}'.");
        }

        return Satisfied(parsed);
    }

    /// <summary>Decides whether the given parsed version falls inside this range.</summary>
    public bool Satisfied(SemanticVersion candidate)
    {
        foreach (var clause in _clauses)
        {
            switch (clause.Operator)
            {
                case '=' when candidate.CompareTo(clause.Version) != 0:
                case '>' when candidate.CompareTo(clause.Version) <= 0:
                case 'G' when candidate.CompareTo(clause.Version) < 0:
                case '<' when candidate.CompareTo(clause.Version) >= 0:
                case 'L' when candidate.CompareTo(clause.Version) > 0:
                    return false;
            }
        }

        return true;
    }

    /// <summary>Renders the canonical clause form used inside advisory metadata.</summary>
    public override string ToString() =>
        _clauses.Length == 0 ? "*" : string.Join(",", _clauses.Select(Render));

    private static string Render(Clause clause)
    {
        var text = clause.Version.ToString();
        return clause.Operator switch
        {
            '=' => "=" + text,
            '>' => ">" + text,
            'G' => ">=" + text,
            '<' => "<" + text,
            _ => "<=" + text
        };
    }

    private readonly record struct Clause(char Operator, SemanticVersion Version);
}

