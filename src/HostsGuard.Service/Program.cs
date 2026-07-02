using System.Runtime.Versioning;
using HostsGuard.Data;
using HostsGuard.Ipc;
using HostsGuard.Service;
using HostsGuard.Windows;

[assembly: SupportedOSPlatform("windows")]

// HostsGuard elevated engine service. Owns all privileged mutation and exposes
// the gRPC control surface over the ACL'd named pipe.

var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
var baseDir = Path.Combine(programData, "HostsGuard");
Directory.CreateDirectory(baseDir);

var dbPath = Path.Combine(baseDir, "hostsguard.db");
var handshakePath = Path.Combine(baseDir, "session_token");

var hosts = new HostsEngine(HostsEngine.DefaultHostsPath);
var db = new HostsDatabase(dbPath);
var firewall = new FirewallEngine();
var identity = new FirewallIdentity(Path.Combine(baseDir, "fw_identities.json"));
var dns = new DnsConfig();
using var listFetcher = new HttpListFetcher();
using var state = new ServiceState(hosts, db, firewall, identity, dns, baseDir, listFetcher);
using var connectionFeed = new ConnectionFeed(state);
connectionFeed.Start();

// Mint a per-session token and publish it to the ACL'd handshake file.
var token = SessionToken.Generate();
SessionToken.WriteHandshake(handshakePath, token);

var app = ServiceHost.Build(state, token);

// Run as a Windows Service when hosted by the SCM; as a console otherwise.
app.Lifetime.ApplicationStopping.Register(() => Console.WriteLine("HostsGuard service stopping."));
Console.WriteLine($"HostsGuard service listening on named pipe '{NamedPipeSecurity.PipeName}'.");
await app.RunAsync();
