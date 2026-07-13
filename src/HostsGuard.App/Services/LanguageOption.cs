namespace HostsGuard.App.Services;

public sealed record LanguageOption(string Tag, string ResourceKey, string NativeName)
{
    public string Name => I18n.T(ResourceKey, NativeName);
}
