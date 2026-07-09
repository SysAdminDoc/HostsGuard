using FluentAssertions;
using HostsGuard.Core;
using Xunit;

namespace HostsGuard.Core.Tests;

public class CsvExportTests
{
    [Theory]
    [InlineData("plain", "plain")]
    [InlineData("Some App, Inc", "\"Some App, Inc\"")]
    [InlineData("quote \"here\"", "\"quote \"\"here\"\"\"")]
    [InlineData("line\r\nbreak", "\"line\r\nbreak\"")]
    public void Cell_preserves_rfc4180_quoting(string value, string expected) =>
        CsvExport.Cell(value).Should().Be(expected);

    [Theory]
    [InlineData("=cmd|' /C calc'!A0", "'=cmd|' /C calc'!A0")]
    [InlineData("+SUM(1,2)", "\"'+SUM(1,2)\"")]
    [InlineData("-10+20", "'-10+20")]
    [InlineData("@HYPERLINK(\"https://example.test\")", "\"'@HYPERLINK(\"\"https://example.test\"\")\"")]
    [InlineData(" \t=SUM(1,2)", "\"' \t=SUM(1,2)\"")]
    public void Cell_neutralizes_spreadsheet_formulas(string value, string expected) =>
        CsvExport.Cell(value).Should().Be(expected);

    [Fact]
    public void AppendRow_writes_crlf_rows()
    {
        var sb = new System.Text.StringBuilder();

        CsvExport.AppendRow(sb, "A", "=B", "C,D");

        sb.ToString().Should().Be("A,'=B,\"C,D\"\r\n");
    }
}
