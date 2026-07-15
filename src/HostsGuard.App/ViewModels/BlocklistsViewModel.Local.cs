using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Google.Protobuf;
using HostsGuard.App.Services;
using HostsGuard.Contracts;
using HostsGuard.Core;

namespace HostsGuard.App.ViewModels;

public sealed partial class BlocklistsViewModel
{
    private byte[] _localPreviewContent = [];

    [ObservableProperty]
    private string _localFileLabel = I18n.T("LocalList_NoFile", "No local file selected.");

    [ObservableProperty]
    private string _localPreviewSummary = I18n.T("LocalList_NoPreview", "Choose a file to preview; preview never changes the hosts file.");

    [ObservableProperty]
    private string _localSourceName = string.Empty;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ImportLocalPreviewCommand))]
    private bool _hasLocalPreview;

    [ObservableProperty]
    private long _localPreviewTotal;

    [ObservableProperty]
    private long _localPreviewAdded;

    [ObservableProperty]
    private long _localPreviewInvalid;

    [RelayCommand]
    public async Task PreviewLocalFileAsync()
    {
        var path = _filePicker.PickFile(
            I18n.T("LocalList_PickTitle", "Choose a local hosts or adblock file"),
            filter: I18n.T("LocalList_FileFilter", "Hosts and adblock files (*.txt;*.hosts;*.list)|*.txt;*.hosts;*.list|All files (*.*)|*.*"));
        if (path is null)
        {
            return;
        }

        ClearLocalPreview();
        LocalSourceName = SourceName(path);

        byte[] content;
        try
        {
            content = await ReadBoundedAsync(path);
        }
        catch (LocalFileTooLargeException)
        {
            LocalPreviewSummary = I18n.T("LocalList_TooLarge", "This file exceeds the {0} MB local-import cap.",
                BlocklistCatalog.MaxBlocklistBytes / 1_000_000);
            StatusText = LocalPreviewSummary;
            return;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            LocalPreviewSummary = I18n.T("LocalList_ReadFailed", "Could not read the local file: {0}", ex.Message);
            StatusText = LocalPreviewSummary;
            return;
        }

        LocalFileLabel = I18n.T("LocalList_Selected", "{0} · {1} · source local:{2}",
            Path.GetFileName(path), FileSizeText(content.LongLength), LocalSourceName);
        if (content.Length == 0)
        {
            LocalPreviewSummary = I18n.T("LocalList_Empty", "The selected file is empty.");
            StatusText = LocalPreviewSummary;
            return;
        }

        await RunServiceActionAsync(I18n.T("LocalList_PreviewAction", "Preview local file"), async () =>
        {
            var result = await _client.Lists.PreviewBlocklistContentAsync(Request(LocalSourceName, content));
            CaptureConnectivityWarnings(result);
            if (!result.Ok)
            {
                LocalPreviewSummary = LocalResultError(result);
                StatusText = LocalPreviewSummary;
                return;
            }

            _localPreviewContent = content;
            LocalPreviewTotal = result.Total;
            LocalPreviewAdded = result.Added;
            LocalPreviewInvalid = result.Invalid;
            HasLocalPreview = true;
            LocalPreviewSummary = I18n.T("LocalList_PreviewReady",
                "Preview ready: {0:N0} parsed, {1:N0} new, {2:N0} invalid. Confirm import to apply the exact previewed bytes.",
                result.Total, result.Added, result.Invalid);
            StatusText = LocalPreviewSummary;
        });
    }

    private bool CanImportLocalPreview() => HasLocalPreview && _localPreviewContent.Length != 0;

    [RelayCommand(CanExecute = nameof(CanImportLocalPreview))]
    public async Task ImportLocalPreviewAsync()
    {
        if (!CanImportLocalPreview())
        {
            return;
        }

        if (!new MutationConfirmation(
                I18n.T("LocalList_ImportTitle", "Import local blocklist"),
                I18n.T("LocalList_ImportTarget", "local:{0} ({1:N0} parsed domains)", LocalSourceName, LocalPreviewTotal),
                I18n.T("LocalList_ImportConsequence",
                    "Apply the previewed file as a non-refreshable local source: {0:N0} new and {1:N0} invalid. Existing manual and allowlisted decisions are preserved.",
                    LocalPreviewAdded, LocalPreviewInvalid))
            .Request(_confirm))
        {
            StatusText = I18n.T("LocalList_ImportCancelled", "Local blocklist import cancelled; the preview was not applied.");
            return;
        }

        await RunServiceActionAsync(I18n.T("LocalList_ImportAction", "Import local file"), async () =>
        {
            StatusText = I18n.T("LocalList_Importing", "Importing previewed content as local:{0}...", LocalSourceName);
            var result = await _client.Lists.ImportBlocklistContentAsync(Request(LocalSourceName, _localPreviewContent));
            CaptureConnectivityWarnings(result);
            if (!result.Ok)
            {
                StatusText = LocalResultError(result);
                return;
            }

            StatusText = FormatResult(result);
            _localPreviewContent = [];
            HasLocalPreview = false;
            LocalPreviewSummary = I18n.T("LocalList_Imported",
                "Imported local:{0}: {1:N0} parsed, {2:N0} newly blocked.", LocalSourceName, result.Total, result.Added);
            await RefreshCoreAsync();
            StatusText = LocalPreviewSummary;
        });
    }

    private static BlocklistContentRequest Request(string name, byte[] content) => new()
    {
        Name = name,
        Content = ByteString.CopyFrom(content),
    };

    private void ClearLocalPreview()
    {
        _localPreviewContent = [];
        HasLocalPreview = false;
        LocalPreviewTotal = 0;
        LocalPreviewAdded = 0;
        LocalPreviewInvalid = 0;
        LocalPreviewSummary = I18n.T("LocalList_NoPreview", "Choose a file to preview; preview never changes the hosts file.");
    }

    private static string LocalResultError(BlocklistResult result) => result.ErrorCode switch
    {
        "hostsguard.error.v1/invalid_encoding" => I18n.T("LocalList_Encoding", "The selected file is not valid UTF-8."),
        "hostsguard.error.v1/content_too_large" => I18n.T("LocalList_TooLarge", "This file exceeds the {0} MB local-import cap.",
            BlocklistCatalog.MaxBlocklistBytes / 1_000_000),
        _ => I18n.T("LocalList_Failed", "Local blocklist operation failed: {0}", result.Message),
    };

    private static string SourceName(string path)
    {
        var name = Path.GetFileNameWithoutExtension(path).Trim();
        if (name.Length == 0)
        {
            name = Path.GetFileName(path).Trim();
        }

        if (name.Length == 0)
        {
            name = "local-blocklist";
        }

        return name.Length <= 120 ? name : name[..120];
    }

    private static async Task<byte[]> ReadBoundedAsync(string path)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
            bufferSize: 64 * 1024, useAsync: true);
        if (stream.Length > BlocklistCatalog.MaxBlocklistBytes)
        {
            throw new LocalFileTooLargeException();
        }

        var content = new byte[(int)stream.Length];
        await stream.ReadExactlyAsync(content);
        return content;
    }

    private static string FileSizeText(long bytes) => bytes < 1024
        ? I18n.T("LocalList_Bytes", "{0} B", bytes)
        : I18n.T("LocalList_Kilobytes", "{0:0.#} KB", bytes / 1024d);

    private sealed class LocalFileTooLargeException : Exception
    {
    }
}
