using System.IO.Compression;

namespace HostsGuard.Core;

/// <summary>
/// Gzip decompression with a hard output cap — port of the Python
/// <c>_gzip_decompress_limited</c>. A malicious "gzip bomb" download can never
/// balloon memory: the cap is enforced while inflating.
/// </summary>
public static class GzipLimited
{
    public static byte[] Decompress(byte[] compressed, int limit, string label = "payload")
    {
        ArgumentNullException.ThrowIfNull(compressed);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(limit);

        using var input = new MemoryStream(compressed);
        using var gzip = new GZipStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();
        var buffer = new byte[65536];
        int read;
        while ((read = gzip.Read(buffer, 0, Math.Min(buffer.Length, limit + 1 - (int)output.Length))) > 0)
        {
            output.Write(buffer, 0, read);
            if (output.Length > limit)
            {
                throw new InvalidOperationException($"{label} exceeds {limit} bytes after decompression");
            }
        }

        return output.ToArray();
    }
}
