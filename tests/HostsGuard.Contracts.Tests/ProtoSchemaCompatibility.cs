using Google.Protobuf.Reflection;

namespace HostsGuard.Contracts.Tests;

internal static class ProtoSchemaCompatibility
{
    internal static IReadOnlyList<string> FindBreakingChanges(
        FileDescriptorProto baseline,
        FileDescriptorProto current)
    {
        var failures = new List<string>();
        var baselineMessages = FlattenMessages(baseline).ToDictionary(x => x.FullName, StringComparer.Ordinal);
        var currentMessages = FlattenMessages(current).ToDictionary(x => x.FullName, StringComparer.Ordinal);

        foreach (var (fullName, oldMessage) in baselineMessages)
        {
            if (!currentMessages.TryGetValue(fullName, out var newMessage))
            {
                failures.Add($"message removed: {fullName}");
                continue;
            }

            RequireReservations(fullName, oldMessage.Descriptor.ReservedName,
                oldMessage.Descriptor.ReservedRange.Select(x => (x.Start, End: x.End - 1)),
                newMessage.Descriptor.ReservedName,
                newMessage.Descriptor.ReservedRange.Select(x => (x.Start, End: x.End - 1)), failures);

            var currentByNumber = newMessage.Descriptor.Field.ToDictionary(x => x.Number);
            foreach (var oldField in oldMessage.Descriptor.Field)
            {
                if (!currentByNumber.TryGetValue(oldField.Number, out var newField))
                {
                    var numberReserved = newMessage.Descriptor.ReservedRange.Any(
                        range => oldField.Number >= range.Start && oldField.Number < range.End);
                    var nameReserved = newMessage.Descriptor.ReservedName.Contains(oldField.Name);
                    if (!numberReserved || !nameReserved)
                    {
                        failures.Add($"field removed without reserving name and number: {fullName}.{oldField.Name} = {oldField.Number}");
                    }
                    continue;
                }

                CompareField(fullName, oldField, newField, failures);
            }
        }

        var baselineEnums = FlattenEnums(baseline).ToDictionary(x => x.FullName, StringComparer.Ordinal);
        var currentEnums = FlattenEnums(current).ToDictionary(x => x.FullName, StringComparer.Ordinal);
        foreach (var (fullName, oldEnum) in baselineEnums)
        {
            if (!currentEnums.TryGetValue(fullName, out var newEnum))
            {
                failures.Add($"enum removed: {fullName}");
                continue;
            }

            RequireReservations(fullName, oldEnum.Descriptor.ReservedName,
                oldEnum.Descriptor.ReservedRange.Select(x => (x.Start, x.End)),
                newEnum.Descriptor.ReservedName,
                newEnum.Descriptor.ReservedRange.Select(x => (x.Start, x.End)), failures);

            var currentByNumber = newEnum.Descriptor.Value.ToLookup(x => x.Number);
            foreach (var oldValue in oldEnum.Descriptor.Value)
            {
                var sameNumber = currentByNumber[oldValue.Number].FirstOrDefault(x => x.Name == oldValue.Name);
                if (sameNumber is not null)
                {
                    continue;
                }

                var numberReserved = newEnum.Descriptor.ReservedRange.Any(
                    range => oldValue.Number >= range.Start && oldValue.Number <= range.End);
                var nameReserved = newEnum.Descriptor.ReservedName.Contains(oldValue.Name);
                if (!numberReserved || !nameReserved)
                {
                    failures.Add($"enum value removed or renumbered without reserving name and number: {fullName}.{oldValue.Name} = {oldValue.Number}");
                }
            }
        }

        return failures;
    }

    private static void CompareField(
        string message,
        FieldDescriptorProto baseline,
        FieldDescriptorProto current,
        ICollection<string> failures)
    {
        var changes = new List<string>();
        if (baseline.Name != current.Name) changes.Add($"name {baseline.Name} -> {current.Name}");
        if (baseline.Type != current.Type) changes.Add($"type {baseline.Type} -> {current.Type}");
        if (baseline.TypeName != current.TypeName) changes.Add($"type-name {baseline.TypeName} -> {current.TypeName}");
        if (baseline.Label != current.Label) changes.Add($"cardinality {baseline.Label} -> {current.Label}");
        if (baseline.HasOneofIndex != current.HasOneofIndex ||
            (baseline.HasOneofIndex && baseline.OneofIndex != current.OneofIndex))
        {
            changes.Add($"oneof {Oneof(baseline)} -> {Oneof(current)}");
        }
        if (baseline.Proto3Optional != current.Proto3Optional)
        {
            changes.Add($"proto3_optional {baseline.Proto3Optional} -> {current.Proto3Optional}");
        }

        if (changes.Count > 0)
        {
            failures.Add($"field changed: {message}.{baseline.Name} = {baseline.Number} ({string.Join(", ", changes)})");
        }
    }

    private static string Oneof(FieldDescriptorProto field) =>
        field.HasOneofIndex ? field.OneofIndex.ToString(System.Globalization.CultureInfo.InvariantCulture) : "none";

    private static void RequireReservations(
        string owner,
        IEnumerable<string> baselineNames,
        IEnumerable<(int Start, int End)> baselineRanges,
        IEnumerable<string> currentNames,
        IEnumerable<(int Start, int End)> currentRanges,
        ICollection<string> failures)
    {
        var names = currentNames.ToHashSet(StringComparer.Ordinal);
        foreach (var name in baselineNames.Where(name => !names.Contains(name)))
        {
            failures.Add($"reserved name unreserved: {owner}.{name}");
        }

        var ranges = currentRanges.ToArray();
        foreach (var range in baselineRanges.Where(
                     baseline => !ranges.Any(current => current.Start <= baseline.Start && current.End >= baseline.End)))
        {
            failures.Add($"reserved range unreserved: {owner} = {range.Start}..{range.End}");
        }
    }

    private static IEnumerable<(string FullName, DescriptorProto Descriptor)> FlattenMessages(FileDescriptorProto file)
    {
        foreach (var message in file.MessageType)
        {
            foreach (var item in FlattenMessage(file.Package, message))
            {
                yield return item;
            }
        }
    }

    private static IEnumerable<(string FullName, DescriptorProto Descriptor)> FlattenMessage(
        string parent,
        DescriptorProto message)
    {
        var fullName = $"{parent}.{message.Name}";
        yield return (fullName, message);
        foreach (var nested in message.NestedType)
        {
            foreach (var item in FlattenMessage(fullName, nested))
            {
                yield return item;
            }
        }
    }

    private static IEnumerable<(string FullName, EnumDescriptorProto Descriptor)> FlattenEnums(FileDescriptorProto file)
    {
        foreach (var item in file.EnumType)
        {
            yield return ($"{file.Package}.{item.Name}", item);
        }

        foreach (var message in FlattenMessages(file))
        {
            foreach (var item in message.Descriptor.EnumType)
            {
                yield return ($"{message.FullName}.{item.Name}", item);
            }
        }
    }
}
