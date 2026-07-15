namespace HostsGuard.Core;

/// <summary>Strict, pure normalization for first-party firewall rule authoring.</summary>
public static class FirewallRuleAuthoring
{
    public const int MaxDescriptionLength = 1024;

    public static bool TryNormalize(
        FwRule input,
        out FwRule normalized,
        out string error,
        IEnumerable<string>? availableInterfaces = null)
    {
        ArgumentNullException.ThrowIfNull(input);
        normalized = input;
        error = string.Empty;
        if (input.Direction is not ("In" or "Out")) return Fail("direction must be In or Out", out normalized, out error);
        if (input.Action is not ("Allow" or "Block")) return Fail("action must be Allow or Block", out normalized, out error);
        if (input.Protocol is not ("TCP" or "UDP" or "Any" or "ICMPv4" or "ICMPv6"))
            return Fail("protocol must be TCP, UDP, Any, ICMPv4, or ICMPv6", out normalized, out error);
        if (!TryNormalizePorts(input.LocalPorts, out var localPorts, out error) ||
            !TryNormalizePorts(input.RemotePorts, out var remotePorts, out error))
        {
            normalized = input;
            return false;
        }

        if (input.Protocol is not ("TCP" or "UDP") && (localPorts != "Any" || remotePorts != "Any"))
            return Fail($"{input.Protocol} rules cannot specify ports; local and remote ports require TCP or UDP", out normalized, out error);
        if (!TryNormalizeInterfaces(input.Interfaces, out var interfaces, out error, availableInterfaces))
        {
            normalized = input;
            return false;
        }

        if (!TryNormalizeDescription(input.Description, out var description, out error))
        {
            normalized = input;
            return false;
        }

        normalized = input with
        {
            LocalPorts = localPorts,
            RemotePorts = remotePorts,
            Interfaces = interfaces,
            Description = description,
        };
        return true;
    }

    public static bool TryNormalizeDescription(string? value, out string normalized, out string error)
    {
        normalized = (value ?? string.Empty).Trim();
        error = string.Empty;
        if (normalized.Length > MaxDescriptionLength)
        {
            error = $"description cannot exceed {MaxDescriptionLength} characters";
            normalized = string.Empty;
            return false;
        }

        if (normalized.Any(char.IsControl))
        {
            error = "description must be a single line of visible text";
            normalized = string.Empty;
            return false;
        }

        return true;
    }

    public static bool TryNormalizePorts(string? value, out string normalized, out string error)
    {
        normalized = "Any";
        error = string.Empty;
        var raw = (value ?? string.Empty).Trim();
        if (raw is "" or "*" || raw.Equals("Any", StringComparison.OrdinalIgnoreCase)) return true;
        var ranges = new List<(int First, int Last)>();
        foreach (var token in raw.Split(',', StringSplitOptions.TrimEntries))
        {
            if (token.Length == 0)
            {
                error = "port lists cannot contain empty entries";
                return false;
            }

            var bounds = token.Split('-', StringSplitOptions.TrimEntries);
            var last = 0;
            if (bounds.Length is < 1 or > 2 || !int.TryParse(bounds[0], out var first) ||
                (bounds.Length == 2 && !int.TryParse(bounds[1], out last)))
            {
                error = $"'{token}' is not a port or port range";
                return false;
            }

            var end = bounds.Length == 1 ? first : last;
            if (first is < 1 or > 65535 || end is < 1 or > 65535 || first > end)
            {
                error = $"'{token}' must be an ascending range within 1-65535";
                return false;
            }

            ranges.Add((first, end));
        }

        ranges.Sort(static (left, right) => left.First != right.First
            ? left.First.CompareTo(right.First) : left.Last.CompareTo(right.Last));
        var merged = new List<(int First, int Last)>();
        foreach (var range in ranges)
        {
            if (merged.Count != 0 && range.First <= merged[^1].Last + 1)
                merged[^1] = (merged[^1].First, Math.Max(merged[^1].Last, range.Last));
            else
                merged.Add(range);
        }

        normalized = string.Join(',', merged.Select(static range =>
            range.First == range.Last ? range.First.ToString(System.Globalization.CultureInfo.InvariantCulture)
                : $"{range.First}-{range.Last}"));
        return true;
    }

    public static bool TryNormalizeInterfaces(
        string? value,
        out string normalized,
        out string error,
        IEnumerable<string>? availableInterfaces = null)
    {
        normalized = "Any";
        error = string.Empty;
        var raw = (value ?? string.Empty).Trim();
        if (raw is "" or "*" || raw.Equals("Any", StringComparison.OrdinalIgnoreCase)) return true;
        var aliases = raw.Split(',', StringSplitOptions.TrimEntries);
        if (aliases.Length > 64 || aliases.Any(static alias => alias.Length is < 1 or > 256 || alias.Any(char.IsControl)))
        {
            error = "interface aliases must be 1-256 visible characters (maximum 64 aliases)";
            return false;
        }

        if (aliases.Any(static alias => alias is "*" || alias.Equals("Any", StringComparison.OrdinalIgnoreCase)))
        {
            error = "Any cannot be combined with named interface aliases";
            return false;
        }

        var canonical = availableInterfaces?.Where(static name => !string.IsNullOrWhiteSpace(name))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToDictionary(static name => name, static name => name, StringComparer.OrdinalIgnoreCase);
        var selected = new List<string>();
        foreach (var alias in aliases.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (canonical is null)
            {
                selected.Add(alias);
                continue;
            }
            if (canonical.TryGetValue(alias, out var actual))
                selected.Add(actual);
            else
            {
                error = $"interface '{alias}' is not available";
                return false;
            }
        }

        normalized = string.Join(',', selected.Order(StringComparer.OrdinalIgnoreCase));
        return true;
    }

    private static bool Fail(string message, out FwRule normalized, out string error)
    {
        normalized = null!;
        error = message;
        return false;
    }
}
