using HostsGuard.App.Services;

namespace HostsGuard.App.Tests;

/// <summary>Test confirm: records prompts and answers a configured verdict.</summary>
internal sealed class FakeConfirm : IConfirm
{
    private readonly bool _answer;

    public FakeConfirm(bool answer) => _answer = answer;

    public List<string> Prompts { get; } = new();

    public bool Confirm(string title, string message)
    {
        Prompts.Add($"{title}: {message}");
        return _answer;
    }
}
