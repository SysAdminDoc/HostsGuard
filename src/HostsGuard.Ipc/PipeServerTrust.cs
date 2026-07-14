using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace HostsGuard.Ipc;

/// <summary>
/// Client-side defense against named-pipe name squatting: before handshaking, the
/// client confirms the connected pipe object is owned by a legitimate HostsGuard
/// server. The pipe ACL and the per-session token already authenticate the caller
/// TO the server; this closes the reverse gap where a process pre-creates the pipe
/// name and impersonates the server to a client.
/// <para>
/// Trusted owners: SYSTEM/Administrators (the production LocalSystem service), the
/// service accounts, and the current user (dev/console runs, where the server is
/// the same interactive user). Any OTHER principal is a squatter. The check is
/// deliberately fail-open — an indeterminate owner (probe failure) is treated as
/// trusted so a hardening check can never break legitimate IPC.
/// </para>
/// </summary>
[SupportedOSPlatform("windows")]
public static class PipeServerTrust
{
    /// <summary>Pure trust decision — testable without a real pipe.</summary>
    public static bool IsTrustedOwner(SecurityIdentifier? owner, SecurityIdentifier? currentUser)
    {
        if (owner is null)
        {
            return true; // indeterminate → fail open, never block legitimate IPC
        }

        if (owner.IsWellKnown(WellKnownSidType.LocalSystemSid)
            || owner.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid)
            || owner.IsWellKnown(WellKnownSidType.LocalServiceSid)
            || owner.IsWellKnown(WellKnownSidType.NetworkServiceSid))
        {
            return true;
        }

        return currentUser is not null && owner.Equals(currentUser);
    }

    /// <summary>
    /// Refuse to proceed if the connected pipe is owned by an untrusted principal.
    /// No-op when the owner is trusted or indeterminate (fail-open).
    /// </summary>
    public static void EnsureTrustedServer(SafePipeHandle? handle)
    {
        var owner = TryGetOwner(handle);
        if (!IsTrustedOwner(owner, TryCurrentUser()))
        {
            throw new IOException(
                $"the HostsGuard control pipe is owned by an untrusted principal ({owner?.Value}) — refusing to connect");
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

    /// <summary>Best-effort read of a connected pipe's object owner; null on any failure.</summary>
    public static SecurityIdentifier? TryGetOwner(SafePipeHandle? handle)
    {
        if (handle is null || handle.IsInvalid || handle.IsClosed)
        {
            return null;
        }

        var descriptor = IntPtr.Zero;
        try
        {
            var rc = GetSecurityInfo(handle, SeKernelObject, OwnerSecurityInformation,
                out var ownerPtr, out _, out _, out _, out descriptor);
            if (rc != 0 || ownerPtr == IntPtr.Zero)
            {
                return null;
            }

            // Copies the SID into managed memory, so freeing the descriptor after is safe.
            return new SecurityIdentifier(ownerPtr);
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or ArgumentException)
        {
            return null;
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
