using System.Text.Json;

namespace HostsGuard.Service;

public sealed partial class ConsentBroker
{
    // â”€â”€â”€ Persistence â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    private sealed class PersistedState
    {
        public string Mode { get; set; } = ModeNormal;

        public Dictionary<string, bool>? PriorOutboundBlock { get; set; }

        public bool ChildInherit { get; set; }

        /// <summary>Deadline for a time-boxed Learning window (NET-101); null = unbounded.</summary>
        public DateTime? LearnUntilUtc { get; set; }

        /// <summary>Publisher CNs whose signed binaries auto-allow without a prompt (NET-113).</summary>
        public List<string> TrustedPublishers { get; set; } = new();

        /// <summary>Folders whose binaries auto-allow without a prompt (NET-117).</summary>
        public List<string> TrustedFolders { get; set; } = new();

        /// <summary>Prompt on unruled inbound connections too (NET-104); default off (noise).</summary>
        public bool InboundConsent { get; set; }

        public List<OnceRule> OnceRules { get; set; } = new();
    }

    private sealed class OnceRule
    {
        public string Name { get; set; } = string.Empty;

        public DateTime ExpiresUtc { get; set; }
    }

    private PersistedState LoadState()
    {
        try
        {
            if (File.Exists(_statePath))
            {
                var loaded = JsonSerializer.Deserialize<PersistedState>(File.ReadAllText(_statePath));
                if (loaded is not null)
                {
                    _onceRules.AddRange(loaded.OnceRules.Select(r => (r.Name, r.ExpiresUtc)));
                    return loaded;
                }
            }
        }
        catch (Exception ex) when (ex is IOException or JsonException)
        {
            // Corrupt state â€” fall back to normal mode rather than fail startup.
        }

        return new PersistedState();
    }

    private void SaveState()
    {
        _state.OnceRules = _onceRules.Select(r => new OnceRule { Name = r.RuleName, ExpiresUtc = r.ExpiresUtc }).ToList();
        var tmp = _statePath + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(_state));
        File.Move(tmp, _statePath, overwrite: true);
    }

}
