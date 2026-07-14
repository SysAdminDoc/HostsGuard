using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace HostsGuard.Ipc;

public enum PipeOwnerProbeFailure
{
    None,
    InvalidHandle,
    AccessDenied,
    MissingOwner,
    InvalidOwner,
    ApiUnavailable,
    NativeFailure,
}

public readonly record struct PipeOwnerProbeResult(
    SecurityIdentifier? Owner,
    PipeOwnerProbeFailure Failure,
    int NativeError = 0)
{
    public bool Succeeded => Failure == PipeOwnerProbeFailure.None && Owner is not null;

    public static PipeOwnerProbeResult Success(SecurityIdentifier owner) =>
        new(owner ?? throw new ArgumentNullException(nameof(owner)), PipeOwnerProbeFailure.None);

    public static PipeOwnerProbeResult Failed(PipeOwnerProbeFailure failure, int nativeError = 0) =>
        failure == PipeOwnerProbeFailure.None
            ? throw new ArgumentOutOfRangeException(nameof(failure))
            : new(null, failure, nativeError);
}

public enum PipeServerTrustDecision
{
    Trusted,
    Untrusted,
    Indeterminate,
}

public sealed class PipeServerTrustException : IOException
{
    public PipeServerTrustException(string errorCode, string message)
        : base($"{errorCode}: {message}") => ErrorCode = errorCode;

    public string ErrorCode { get; }
}

/// <summary>
/// Client-side defense against named-pipe name squatting: before handshaking, the
/// client confirms the connected pipe object is owned by a legitimate HostsGuard
/// server. The pipe ACL and the per-session token already authenticate the caller
/// TO the server; this closes the reverse gap where a process pre-creates the pipe
/// name and impersonates the server to a client.
/// <para>
/// Trusted owners: SYSTEM/Administrators (the production LocalSystem service), the
/// built-in service accounts, and the current user (dev/console runs, where the
/// server is the same interactive user). Any OTHER principal is a squatter. An
/// invalid handle, access-denied result, unavailable API, missing/invalid owner,
/// or indeterminate current user fails closed before a stream is returned.
/// </para>
/// </summary>
[SupportedOSPlatform("windows")]
public static class PipeServerTrust
{
    public const string UntrustedOwnerError = "hostsguard.error.v1/pipe_owner_untrusted";
    public const string IndeterminateOwnerError = "hostsguard.error.v1/pipe_owner_indeterminate";
    public const string InvalidHandleError = "hostsguard.error.v1/pipe_owner_invalid_handle";
    public const string AccessDeniedError = "hostsguard.error.v1/pipe_owner_probe_access_denied";
    public const string ProbeUnavailableError = "hostsguard.error.v1/pipe_owner_probe_unavailable";
    public const string ProbeFailedError = "hostsguard.error.v1/pipe_owner_probe_failed";

    /// <summary>Pure trust decision — testable without a real pipe.</summary>
    public static PipeServerTrustDecision EvaluateOwner(
        SecurityIdentifier? owner,
        SecurityIdentifier? currentUser)
    {
        if (owner is null)
        {
            return PipeServerTrustDecision.Indeterminate;
        }

        if (owner.IsWellKnown(WellKnownSidType.LocalSystemSid)
            || owner.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid)
            || owner.IsWellKnown(WellKnownSidType.LocalServiceSid)
            || owner.IsWellKnown(WellKnownSidType.NetworkServiceSid))
        {
            return PipeServerTrustDecision.Trusted;
        }

        if (currentUser is null)
        {
            return PipeServerTrustDecision.Indeterminate;
        }

        return owner.Equals(currentUser)
            ? PipeServerTrustDecision.Trusted
            : PipeServerTrustDecision.Untrusted;
    }

    public static bool IsTrustedOwner(SecurityIdentifier? owner, SecurityIdentifier? currentUser) =>
        EvaluateOwner(owner, currentUser) == PipeServerTrustDecision.Trusted;

    /// <summary>
    /// Refuse to proceed unless the connected pipe has a proven trusted owner.
    /// </summary>
    public static void EnsureTrustedServer(SafePipeHandle? handle)
        => EnsureTrustedServer(ProbeOwner(handle), TryCurrentUser());

    /// <summary>Apply the fail-closed decision to a typed probe result.</summary>
    public static void EnsureTrustedServer(
        PipeOwnerProbeResult probe,
        SecurityIdentifier? currentUser)
    {
        if (!probe.Succeeded)
        {
            var (code, message) = probe.Failure switch
            {
                PipeOwnerProbeFailure.InvalidHandle => (InvalidHandleError, "the control-pipe handle is invalid"),
                PipeOwnerProbeFailure.AccessDenied => (AccessDeniedError, "access to the control-pipe owner was denied"),
                PipeOwnerProbeFailure.ApiUnavailable => (ProbeUnavailableError, "the Windows owner-probe API is unavailable"),
                PipeOwnerProbeFailure.None or PipeOwnerProbeFailure.MissingOwner or PipeOwnerProbeFailure.InvalidOwner =>
                    (IndeterminateOwnerError, "the control-pipe owner is indeterminate"),
                _ => (ProbeFailedError, probe.NativeError == 0
                    ? "the control-pipe owner probe failed"
                    : $"the control-pipe owner probe failed with Windows error {probe.NativeError}"),
            };
            throw new PipeServerTrustException(code, message);
        }

        switch (EvaluateOwner(probe.Owner, currentUser))
        {
            case PipeServerTrustDecision.Trusted:
                return;
            case PipeServerTrustDecision.Untrusted:
                throw new PipeServerTrustException(
                    UntrustedOwnerError,
                    "the control pipe is owned by an untrusted principal");
            default:
                throw new PipeServerTrustException(
                    IndeterminateOwnerError,
                    "the control-pipe owner could not be compared with the current user");
        }
    }

    private const int SeKernelObject = 6;
    private const int OwnerSecurityInformation = 0x00000001;

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint GetSecurityInfo(
        SafePipeHandle handle,
        int objectType,
        int securityInfo,
        out IntPtr ppsidOwner,
        out IntPtr ppsidGroup,
        out IntPtr ppDacl,
        out IntPtr ppSacl,
        out IntPtr ppSecurityDescriptor);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr hMem);

    /// <summary>Read a connected pipe's object owner with a typed failure result.</summary>
    public static PipeOwnerProbeResult ProbeOwner(SafePipeHandle? handle)
    {
        if (handle is null || handle.IsInvalid || handle.IsClosed)
        {
            return PipeOwnerProbeResult.Failed(PipeOwnerProbeFailure.InvalidHandle);
        }

        var descriptor = IntPtr.Zero;
        try
        {
            var rc = GetSecurityInfo(handle, SeKernelObject, OwnerSecurityInformation,
                out var ownerPtr, out _, out _, out _, out descriptor);
            if (rc != 0)
            {
                return PipeOwnerProbeResult.Failed(
                    rc == 5 ? PipeOwnerProbeFailure.AccessDenied : PipeOwnerProbeFailure.NativeFailure,
                    unchecked((int)rc));
            }

            if (ownerPtr == IntPtr.Zero)
            {
                return PipeOwnerProbeResult.Failed(PipeOwnerProbeFailure.MissingOwner);
            }

            // Copies the SID into managed memory, so freeing the descriptor after is safe.
            return PipeOwnerProbeResult.Success(new SecurityIdentifier(ownerPtr));
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            return PipeOwnerProbeResult.Failed(PipeOwnerProbeFailure.ApiUnavailable);
        }
        catch (ArgumentException)
        {
            return PipeOwnerProbeResult.Failed(PipeOwnerProbeFailure.InvalidOwner);
        }
        catch (ObjectDisposedException)
        {
            return PipeOwnerProbeResult.Failed(PipeOwnerProbeFailure.InvalidHandle);
        }
        finally
        {
            if (descriptor != IntPtr.Zero)
            {
                LocalFree(descriptor);
            }
        }
    }

    private static SecurityIdentifier? TryCurrentUser()
    {
        try
        {
            return WindowsIdentity.GetCurrent().User;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException)
        {
            return null;
        }
    }
}
