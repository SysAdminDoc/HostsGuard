using System.Collections.Generic;
using System.Reflection;
using System.Text;
using FluentAssertions;
using HostsGuard.Windows;
using Xunit;

namespace HostsGuard.Windows.Tests;

/// <summary>
/// NET-109: the raw-packet layer extracts a ClientHello SNI from a TCP/443
/// segment and reports the destination IP; non-443 and non-TCP packets are
/// ignored.
/// </summary>
public class SniSnifferTests
{
    private static byte[] MinimalClientHello(string host)
    {
        var name = Encoding.ASCII.GetBytes(host);
        var entry = new List<byte> { 0x00, (byte)(name.Length >> 8), (byte)(name.Length & 0xff) };
        entry.AddRange(name);
        var list = new List<byte> { (byte)(entry.Count >> 8), (byte)(entry.Count & 0xff) };
        list.AddRange(entry);
        var ext = new List<byte> { 0x00, 0x00, (byte)(list.Count >> 8), (byte)(list.Count & 0xff) };
        ext.AddRange(list);

        var hello = new List<byte> { 0x03, 0x03 };
        hello.AddRange(new byte[32]);
        hello.Add(0x00);
        hello.AddRange(new byte[] { 0x00, 0x02, 0x00, 0x2f });
        hello.AddRange(new byte[] { 0x01, 0x00 });
        hello.Add((byte)(ext.Count >> 8));
        hello.Add((byte)(ext.Count & 0xff));
        hello.AddRange(ext);

        var hs = new List<byte> { 0x01, (byte)(hello.Count >> 16), (byte)(hello.Count >> 8), (byte)(hello.Count & 0xff) };
        hs.AddRange(hello);
        var record = new List<byte> { 0x16, 0x03, 0x01, (byte)(hs.Count >> 8), (byte)(hs.Count & 0xff) };
        record.AddRange(hs);
        return record.ToArray();
    }

    private static byte[] Ipv4Tcp(byte[] payload, int destPort, byte protocol = 6, byte[]? destIp = null)
    {
        destIp ??= new byte[] { 203, 0, 113, 42 };
        var tcp = new byte[20 + payload.Length];
        tcp[2] = (byte)(destPort >> 8);
        tcp[3] = (byte)(destPort & 0xff);
        tcp[12] = 0x50; // data offset = 5 words (20 bytes)
        payload.CopyTo(tcp, 20);

        var ip = new byte[20 + tcp.Length];
        ip[0] = 0x45;             // version 4, IHL 5
        ip[9] = protocol;         // TCP
        destIp.CopyTo(ip, 16);    // destination address
        tcp.CopyTo(ip, 20);
        return ip;
    }

    [Fact]
    public void Extracts_sni_and_destination_ip_from_a_443_segment()
    {
        SniObservation? seen = null;
        using var sniffer = new SniSniffer(o => seen = o);
        sniffer.Inspect(Ipv4Tcp(MinimalClientHello("sni.example.org"), destPort: 443));

        seen.Should().NotBeNull();
        seen!.Host.Should().Be("sni.example.org");
        seen.RemoteAddress.Should().Be("203.0.113.42");
        seen.EchUnavailable.Should().BeFalse();
    }

    [Fact]
    public void Ignores_non_443_traffic()
    {
        SniObservation? seen = null;
        using var sniffer = new SniSniffer(o => seen = o);
        sniffer.Inspect(Ipv4Tcp(MinimalClientHello("nope.example.org"), destPort: 80));
        seen.Should().BeNull();
    }

    [Fact]
    public void Ignores_non_tcp_packets()
    {
        SniObservation? seen = null;
        using var sniffer = new SniSniffer(o => seen = o);
        sniffer.Inspect(Ipv4Tcp(MinimalClientHello("udp.example.org"), destPort: 443, protocol: 17));
        seen.Should().BeNull();
    }

    [Fact]
    public void Capture_selection_prefers_default_route_and_skips_host_virtual_adapters()
    {
        var physical = System.Net.IPAddress.Parse("192.168.1.20");
        var wsl = System.Net.IPAddress.Parse("172.22.64.1");
        var hostOnly = System.Net.IPAddress.Parse("192.168.116.1");

        var selected = SniSniffer.SelectCaptureAddresses([
            new(wsl, HasGateway: false, IsHostVirtualAdapter: true),
            new(hostOnly, HasGateway: false, IsHostVirtualAdapter: true),
            new(physical, HasGateway: true, IsHostVirtualAdapter: false),
        ]);

        selected.Should().Equal(physical);
    }

    [Fact]
    public void Capture_selection_falls_back_when_only_virtual_default_route_exists()
    {
        var vpn = System.Net.IPAddress.Parse("10.8.0.2");
        var selected = SniSniffer.SelectCaptureAddresses([
            new(vpn, HasGateway: true, IsHostVirtualAdapter: true),
        ]);

        selected.Should().Equal(vpn);
    }

    [Fact]
    public void Stop_waits_for_pump_threads_to_exit()
    {
        using var sniffer = new SniSniffer(_ => { });
        var cts = Field<CancellationTokenSource>(sniffer, "_cts");
        var stopped = new ManualResetEventSlim();
        var pump = new Thread(() =>
        {
            while (!cts.IsCancellationRequested)
            {
                Thread.Sleep(1);
            }

            Thread.Sleep(150);
            stopped.Set();
        })
        {
            IsBackground = true,
            Name = "HostsGuardSniTest",
        };
        Field<List<Thread>>(sniffer, "_pumps").Add(pump);
        SetField(sniffer, "_active", true);
        pump.Start();

        sniffer.Stop();

        stopped.IsSet.Should().BeTrue();
        pump.IsAlive.Should().BeFalse();
        sniffer.Active.Should().BeFalse();
        Field<List<Thread>>(sniffer, "_pumps").Should().BeEmpty();
    }

    private static T Field<T>(SniSniffer sniffer, string name) where T : class =>
        (T)typeof(SniSniffer).GetField(name, BindingFlags.Instance | BindingFlags.NonPublic)!
            .GetValue(sniffer)!;

    private static void SetField<T>(SniSniffer sniffer, string name, T value) =>
        typeof(SniSniffer).GetField(name, BindingFlags.Instance | BindingFlags.NonPublic)!
            .SetValue(sniffer, value);
}
