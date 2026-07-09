using System.Text;

namespace HostsGuard.Core;

public static class CsvExport
{
    private static readonly char[] QuoteTriggers = [',', '"', '\n', '\r'];
    private static readonly char[] FormulaTriggers = ['=', '+', '-', '@'];

    public static string Cell(string? value)
    {
        var safe = NeutralizeFormula(value ?? string.Empty);
        return safe.IndexOfAny(QuoteTriggers) >= 0
            ? "\"" + safe.Replace("\"", "\"\"", StringComparison.Ordinal) + "\""
            : safe;
    }

    public static void AppendRow(StringBuilder sb, params string?[] columns)
    {
        for (var i = 0; i < columns.Length; i++)
        {
            if (i != 0)
            {
                sb.Append(',');
            }

            sb.Append(Cell(columns[i]));
        }

        sb.Append("\r\n");
    }

    private static string NeutralizeFormula(string value)
    {
        var clean = value.AsSpan().TrimStart();
        return clean.Length > 0 && FormulaTriggers.Contains(clean[0])
            ? "'" + value
            : value;
    }
}
