using System.Net;
using System.Net.Sockets;

namespace HostsGuard.App.Services;

/// <summary>
/// Comparable address key shared by network grids. Ascending order is stable:
/// <c>Any</c>, <c>LocalSubnet</c>, numeric IPv4, normalized IPv6 (then scope
/// id), and finally invalid/raw specifications by ordinal text. Display values
/// are never normalized or discarded.
/// </summary>
public sealed class NetworkAddressSortKey : IComparable<NetworkAddressSortKey>, IComparable
{
    private const int SentinelCategory = 0;
    private const int Ipv4Category = 1;
    private const int Ipv6Category = 2;
    private const int RawCategory = 3;

    private readonly int _category;
    private readonly int _sentinelRank;
    private readonly byte[] _addressBytes;
    private readonly long _scopeId;
    private readonly string _raw;

    private NetworkAddressSortKey(
        int category,
        string raw,
        int sentinelRank = 0,
        byte[]? addressBytes = null,
        long scopeId = 0)
    {
        _category = category;
        _raw = raw;
        _sentinelRank = sentinelRank;
        _addressBytes = addressBytes ?? [];
        _scopeId = scopeId;
    }

    public static NetworkAddressSortKey Create(string? value)
    {
        var raw = (value ?? string.Empty).Trim();
        if (raw.Equals("Any", StringComparison.OrdinalIgnoreCase) || raw == "*")
        {
            return new NetworkAddressSortKey(SentinelCategory, raw, sentinelRank: 0);
        }

        if (raw.Equals("LocalSubnet", StringComparison.OrdinalIgnoreCase))
        {
            return new NetworkAddressSortKey(SentinelCategory, raw, sentinelRank: 1);
        }

        if (IPAddress.TryParse(UnwrapBrackets(raw), out var address))
        {
            var category = address.AddressFamily == AddressFamily.InterNetwork
                ? Ipv4Category
                : Ipv6Category;
            var scopeId = address.AddressFamily == AddressFamily.InterNetworkV6
                ? address.ScopeId
                : 0;
            return new NetworkAddressSortKey(
                category,
                raw,
                addressBytes: address.GetAddressBytes(),
                scopeId: scopeId);
        }

        return new NetworkAddressSortKey(RawCategory, raw);
    }

    public int CompareTo(NetworkAddressSortKey? other)
    {
        if (other is null)
        {
            return 1;
        }

        var result = _category.CompareTo(other._category);
        if (result != 0)
        {
            return result;
        }

        if (_category == SentinelCategory)
        {
            return _sentinelRank.CompareTo(other._sentinelRank);
        }

        if (_category is Ipv4Category or Ipv6Category)
        {
            result = CompareBytes(_addressBytes, other._addressBytes);
            if (result != 0)
            {
                return result;
            }

            result = _scopeId.CompareTo(other._scopeId);
            if (result != 0)
            {
                return result;
            }
        }

        result = StringComparer.OrdinalIgnoreCase.Compare(_raw, other._raw);
        return result != 0 ? result : StringComparer.Ordinal.Compare(_raw, other._raw);
    }

    int IComparable.CompareTo(object? obj) => obj switch
    {
        null => 1,
        NetworkAddressSortKey other => CompareTo(other),
        _ => throw new ArgumentException($"Expected {nameof(NetworkAddressSortKey)}", nameof(obj)),
    };

    public override string ToString() => _raw;

    private static string UnwrapBrackets(string value) =>
        value.Length > 2 && value[0] == '[' && value[^1] == ']'
            ? value[1..^1]
            : value;

    private static int CompareBytes(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        var length = Math.Min(left.Length, right.Length);
        for (var index = 0; index < length; index++)
        {
            var result = left[index].CompareTo(right[index]);
            if (result != 0)
            {
                return result;
            }
        }

        return left.Length.CompareTo(right.Length);
    }
}
