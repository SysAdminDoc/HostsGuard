using System.Collections.Generic;
using System.Text;
using FluentAssertions;
using HostsGuard.Core;
using Xunit;

namespace HostsGuard.Core.Tests;

/// <summary>
/// NET-109: the TLS ClientHello SNI parser recovers the hostname, reports ECH as
/// unavailable, and never throws on truncated or non-TLS input.
/// </summary>
public class TlsClientHelloTests
{
    /// <summary>Build a ClientHello record with the given extensions appended.</summary>
    private static byte[] ClientHello(IEnumerable<byte> extensions)
    {
        var ext = new List<byte>(extensions);
        var hello = new List<byte> { 0x03, 0x03 };          // client_version TLS1.2
        hello.AddRange(new byte[32]);                        // random
        hello.Add(0x00);                                     // session_id length 0
        hello.AddRange(new byte[] { 0x00, 0x02, 0x00, 0x2f }); // cipher_suites (1 suite)
        hello.AddRange(new byte[] { 0x01, 0x00 });           // compression_methods: null
        hello.Add((byte)(ext.Count >> 8));                   // extensions length
        hello.Add((byte)(ext.Count & 0xff));
        hello.AddRange(ext);

        var handshake = new List<byte> { 0x01 };             // ClientHello
        handshake.Add((byte)(hello.Count >> 16));
        handshake.Add((byte)(hello.Count >> 8));
        handshake.Add((byte)(hello.Count & 0xff));
        handshake.AddRange(hello);

        var record = new List<byte> { 0x16, 0x03, 0x01 };    // handshake, TLS1.0 record
        record.Add((byte)(handshake.Count >> 8));
        record.Add((byte)(handshake.Count & 0xff));
        record.AddRange(handshake);
        return record.ToArray();
    }

    private static byte[] SniExtension(string host)
    {
        var name = Encoding.ASCII.GetBytes(host);
        var entry = new List<byte> { 0x00 };                 // name_type host_name
        entry.Add((byte)(name.Length >> 8));
        entry.Add((byte)(name.Length & 0xff));
        entry.AddRange(name);

        var list = new List<byte> { (byte)(entry.Count >> 8), (byte)(entry.Count & 0xff) };
        list.AddRange(entry);

        var ext = new List<byte> { 0x00, 0x00 };             // ext type server_name
        ext.Add((byte)(list.Count >> 8));
        ext.Add((byte)(list.Count & 0xff));
        ext.AddRange(list);
        return ext.ToArray();
    }

    private static byte[] EchExtension()
        => new byte[] { 0xfe, 0x0d, 0x00, 0x03, 0x01, 0x02, 0x03 }; // ECH ext, 3 bytes payload

    [Fact]
    public void Recovers_the_sni_hostname()
    {
        var result = TlsClientHello.TryParse(ClientHello(SniExtension("cdn.example.com")));
        result.Found.Should().BeTrue();
        result.Host.Should().Be("cdn.example.com");
        result.EchUnavailable.Should().BeFalse();
    }

    [Fact]
    public void Ech_marks_the_sni_as_unavailable()
    {
        // ECH present alongside a public/outer SNI — the real name is encrypted.
        var ext = new List<byte>();
        ext.AddRange(SniExtension("public.example.net"));
        ext.AddRange(EchExtension());
        var result = TlsClientHello.TryParse(ClientHello(ext));
        result.Found.Should().BeFalse();
        result.EchUnavailable.Should().BeTrue();
    }

    [Fact]
    public void Non_tls_input_yields_none()
        => TlsClientHello.TryParse(new byte[] { 0x47, 0x45, 0x54, 0x20 }).Should().Be(TlsClientHello.Result.None);

    [Fact]
    public void Truncated_clienthello_does_not_throw()
    {
        var full = ClientHello(SniExtension("cut.example.com"));
        var act = () => TlsClientHello.TryParse(full.AsSpan(0, full.Length - 10).ToArray());
        act.Should().NotThrow();
    }

    [Fact]
    public void No_sni_extension_yields_none()
        => TlsClientHello.TryParse(ClientHello(System.Array.Empty<byte>())).Found.Should().BeFalse();
}
