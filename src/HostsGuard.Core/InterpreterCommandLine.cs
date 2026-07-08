namespace HostsGuard.Core;

public sealed record InterpreterCommandBinding(
    string Display,
    string ScriptKey,
    string ScriptPath);

public static class InterpreterCommandLine
{
    private static readonly HashSet<string> Interpreters = new(StringComparer.OrdinalIgnoreCase)
    {
        "python",
        "pythonw",
        "node",
        "pwsh",
        "powershell",
        "java",
        "wscript",
        "cscript",
    };

    public static InterpreterCommandBinding? TryCreate(string application, string commandLine)
    {
        var exe = Path.GetFileNameWithoutExtension(application);
        if (exe.Length == 0 || !Interpreters.Contains(exe) || string.IsNullOrWhiteSpace(commandLine))
        {
            return null;
        }

        var args = Split(commandLine);
        if (args.Count == 0)
        {
            return null;
        }

        if (LooksLikeExecutable(args[0], application, exe))
        {
            args.RemoveAt(0);
        }

        var script = FindScript(exe, args);
        if (script.Length == 0)
        {
            return null;
        }

        var displayExe = exe.Equals("powershell", StringComparison.OrdinalIgnoreCase) ? "powershell" : exe;
        var display = $"{displayExe} {script}";
        var key = $"{Path.GetFullPath(application).ToLowerInvariant()}|{script.ToLowerInvariant()}";
        return new InterpreterCommandBinding(display, key, script);
    }

    public static List<string> Split(string commandLine)
    {
        var args = new List<string>();
        var current = new System.Text.StringBuilder();
        var inQuotes = false;
        for (var i = 0; i < commandLine.Length; i++)
        {
            var ch = commandLine[i];
            if (ch == '"')
            {
                inQuotes = !inQuotes;
                continue;
            }

            if (char.IsWhiteSpace(ch) && !inQuotes)
            {
                Flush();
                continue;
            }

            current.Append(ch);
        }

        Flush();
        return args;

        void Flush()
        {
            if (current.Length == 0)
            {
                return;
            }

            args.Add(current.ToString());
            current.Clear();
        }
    }

    private static bool LooksLikeExecutable(string arg, string application, string exe)
        => string.Equals(Path.GetFileNameWithoutExtension(arg), exe, StringComparison.OrdinalIgnoreCase)
           || string.Equals(arg, application, StringComparison.OrdinalIgnoreCase);

    private static string FindScript(string exe, IReadOnlyList<string> args)
    {
        for (var i = 0; i < args.Count; i++)
        {
            var arg = args[i];
            if (string.IsNullOrWhiteSpace(arg))
            {
                continue;
            }

            if (exe is "wscript" or "cscript" && arg.StartsWith("//", StringComparison.Ordinal))
            {
                continue;
            }

            if (arg.StartsWith("-", StringComparison.Ordinal))
            {
                if (exe is "pwsh" or "powershell")
                {
                    if (IsPowerShellFileSwitch(arg) && i + 1 < args.Count)
                    {
                        return args[i + 1];
                    }

                    if (arg.Equals("-Command", StringComparison.OrdinalIgnoreCase)
                        || arg.Equals("-EncodedCommand", StringComparison.OrdinalIgnoreCase))
                    {
                        return string.Empty;
                    }
                }
                else if (exe is "python" or "pythonw")
                {
                    if (arg.Equals("-c", StringComparison.OrdinalIgnoreCase))
                    {
                        return string.Empty;
                    }

                    if (arg.Equals("-m", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Count)
                    {
                        return "-m " + args[i + 1];
                    }
                }
                else if (exe == "node")
                {
                    if (IsNodeInlineSwitch(arg))
                    {
                        return string.Empty;
                    }

                    if (NodeOptionConsumesValue(arg) && i + 1 < args.Count)
                    {
                        i++;
                    }
                }
                else if (exe == "java")
                {
                    if (arg.Equals("-jar", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Count)
                    {
                        return args[i + 1];
                    }

                    if (JavaOptionConsumesValue(arg) && i + 1 < args.Count)
                    {
                        i++;
                    }
                }

                continue;
            }

            return arg;
        }

        return string.Empty;
    }

    private static bool IsPowerShellFileSwitch(string value)
        => value.Equals("-File", StringComparison.OrdinalIgnoreCase)
           || value.Equals("-f", StringComparison.OrdinalIgnoreCase);

    private static bool IsNodeInlineSwitch(string value)
        => value.Equals("-e", StringComparison.OrdinalIgnoreCase)
           || value.Equals("--eval", StringComparison.OrdinalIgnoreCase)
           || value.Equals("-p", StringComparison.OrdinalIgnoreCase)
           || value.Equals("--print", StringComparison.OrdinalIgnoreCase);

    private static bool NodeOptionConsumesValue(string value)
        => value.Equals("-r", StringComparison.OrdinalIgnoreCase)
           || value.Equals("--require", StringComparison.OrdinalIgnoreCase)
           || value.Equals("--import", StringComparison.OrdinalIgnoreCase)
           || value.Equals("--loader", StringComparison.OrdinalIgnoreCase)
           || value.Equals("--experimental-loader", StringComparison.OrdinalIgnoreCase);

    private static bool JavaOptionConsumesValue(string value)
        => value.Equals("-cp", StringComparison.OrdinalIgnoreCase)
           || value.Equals("-classpath", StringComparison.OrdinalIgnoreCase)
           || value.Equals("--class-path", StringComparison.OrdinalIgnoreCase)
           || value.Equals("-modulepath", StringComparison.OrdinalIgnoreCase)
           || value.Equals("--module-path", StringComparison.OrdinalIgnoreCase);
}
