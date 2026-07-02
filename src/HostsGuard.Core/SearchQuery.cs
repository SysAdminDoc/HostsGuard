using System.Text;

namespace HostsGuard.Core;

/// <summary>One parsed search term.</summary>
public sealed record SearchTerm(string Field, SearchOp Op, string Value);

public enum SearchOp
{
    Contains,
    NotContains,
    NotEqual,
}

/// <summary>
/// Shared table-search DSL supporting <c>field:value</c>, <c>!term</c>, and
/// <c>field!=value</c>. Faithful port of Python <c>_parse_search_query</c> /
/// <c>_search_matches</c>, including shell-like tokenization with quote handling
/// and a whitespace-split fallback on unbalanced quotes.
/// </summary>
public static class SearchQuery
{
    /// <summary>Tokenize + parse a query string into terms.</summary>
    public static IReadOnlyList<SearchTerm> Parse(string? query)
    {
        var q = (query ?? string.Empty).Trim();
        if (q.Length == 0)
        {
            return Array.Empty<SearchTerm>();
        }

        var tokens = ShellSplit(q, out var ok);
        if (!ok)
        {
            tokens = q.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries).ToList();
        }

        var parsed = new List<SearchTerm>();
        foreach (var raw in tokens)
        {
            var token = raw.Trim();
            if (token.Length == 0)
            {
                continue;
            }

            if (token.Contains("!=", StringComparison.Ordinal) && !token.StartsWith("!=", StringComparison.Ordinal))
            {
                var i = token.IndexOf("!=", StringComparison.Ordinal);
                parsed.Add(new SearchTerm(token[..i].Trim().ToLowerInvariant(), SearchOp.NotEqual, token[(i + 2)..].Trim().ToLowerInvariant()));
            }
            else if (token.StartsWith('!') && token.Length > 1)
            {
                parsed.Add(new SearchTerm(string.Empty, SearchOp.NotContains, token[1..].Trim().ToLowerInvariant()));
            }
            else if (token.Contains(':', StringComparison.Ordinal) && !token.StartsWith(':'))
            {
                var i = token.IndexOf(':', StringComparison.Ordinal);
                parsed.Add(new SearchTerm(token[..i].Trim().ToLowerInvariant(), SearchOp.Contains, token[(i + 1)..].Trim().ToLowerInvariant()));
            }
            else
            {
                parsed.Add(new SearchTerm(string.Empty, SearchOp.Contains, token.ToLowerInvariant()));
            }
        }

        return parsed.Where(p => p.Value.Length != 0 || p.Op == SearchOp.NotEqual).ToList();
    }

    /// <summary>
    /// Whether a record matches the query. A record maps field names to values;
    /// a value may be a string or a collection of strings. Field aliases are
    /// resolved before lookup.
    /// </summary>
    public static bool Matches(
        IReadOnlyDictionary<string, object?> record,
        string? query,
        IReadOnlyDictionary<string, string>? aliases = null)
    {
        ArgumentNullException.ThrowIfNull(record);
        var terms = Parse(query);
        if (terms.Count == 0)
        {
            return true;
        }

        var aliasMap = new Dictionary<string, string>(StringComparer.Ordinal);
        if (aliases is not null)
        {
            foreach (var kv in aliases)
            {
                aliasMap[kv.Key.ToLowerInvariant()] = kv.Value.ToLowerInvariant();
            }
        }

        var normalized = new Dictionary<string, object?>(StringComparer.Ordinal);
        foreach (var kv in record)
        {
            normalized[kv.Key.ToLowerInvariant()] = kv.Value;
        }

        foreach (var term in terms)
        {
            var field = aliasMap.GetValueOrDefault(term.Field, term.Field);
            var val = term.Value;
            switch (term.Op)
            {
                case SearchOp.Contains:
                    if (!RecordText(normalized, field).Contains(val, StringComparison.Ordinal))
                    {
                        return false;
                    }

                    break;
                case SearchOp.NotContains:
                    if (RecordText(normalized, string.Empty).Contains(val, StringComparison.Ordinal))
                    {
                        return false;
                    }

                    break;
                case SearchOp.NotEqual:
                    if (field.Length == 0)
                    {
                        return false;
                    }

                    var rawVal = (normalized.GetValueOrDefault(field)?.ToString() ?? string.Empty).Trim().ToLowerInvariant();
                    if (rawVal == val)
                    {
                        return false;
                    }

                    break;
                default:
                    break;
            }
        }

        return true;
    }

    private static string RecordText(IReadOnlyDictionary<string, object?> record, string field)
    {
        var values = new List<string>();
        if (field.Length != 0)
        {
            var v = record.GetValueOrDefault(field);
            AppendValue(values, v);
        }
        else
        {
            foreach (var v in record.Values)
            {
                AppendValue(values, v);
            }
        }

        return string.Join(' ', values).ToLowerInvariant();
    }

    private static void AppendValue(List<string> acc, object? v)
    {
        if (v is string s)
        {
            acc.Add(s);
        }
        else if (v is System.Collections.IEnumerable en)
        {
            foreach (var item in en)
            {
                acc.Add(item?.ToString() ?? string.Empty);
            }
        }
        else
        {
            acc.Add(v?.ToString() ?? string.Empty);
        }
    }

    /// <summary>
    /// POSIX-shell-like tokenizer (subset of Python <c>shlex.split</c>): whitespace
    /// separates, single and double quotes group, backslash escapes the next char.
    /// Sets <paramref name="ok"/> to false on an unterminated quote.
    /// </summary>
    private static List<string> ShellSplit(string s, out bool ok)
    {
        var tokens = new List<string>();
        var cur = new StringBuilder();
        var inToken = false;
        var quote = '\0';
        ok = true;

        for (var i = 0; i < s.Length; i++)
        {
            var c = s[i];
            if (quote != '\0')
            {
                if (c == quote)
                {
                    quote = '\0';
                }
                else if (c == '\\' && quote == '"' && i + 1 < s.Length)
                {
                    cur.Append(s[++i]);
                }
                else
                {
                    cur.Append(c);
                }

                continue;
            }

            switch (c)
            {
                case '\'':
                case '"':
                    quote = c;
                    inToken = true;
                    break;
                case '\\' when i + 1 < s.Length:
                    cur.Append(s[++i]);
                    inToken = true;
                    break;
                case ' ':
                case '\t':
                case '\n':
                case '\r':
                    if (inToken)
                    {
                        tokens.Add(cur.ToString());
                        cur.Clear();
                        inToken = false;
                    }

                    break;
                default:
                    cur.Append(c);
                    inToken = true;
                    break;
            }
        }

        if (quote != '\0')
        {
            ok = false;
            return tokens;
        }

        if (inToken)
        {
            tokens.Add(cur.ToString());
        }

        return tokens;
    }
}
