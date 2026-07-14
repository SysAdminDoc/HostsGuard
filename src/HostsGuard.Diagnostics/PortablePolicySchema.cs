using System.Text.Json;
using System.Text.Json.Nodes;
using HostsGuard.Core;
using Json.Schema;
using Json.Schema.Generation;

namespace HostsGuard.Diagnostics;

/// <summary>One schema-validation error at a precise JSON Pointer location.</summary>
public sealed record PolicyValidationError(string Pointer, string Message);

/// <summary>
/// Machine-readable contract for the portable-policy JSON document. The schema is
/// GENERATED from <see cref="PortablePolicy"/> so it can never silently drift from
/// the model. Presence is intentionally lenient — the exporter omits empty
/// optional members (<c>WhenWritingNull</c>) — so property <c>required</c>
/// constraints are stripped; validation still catches wrong types and malformed
/// structure and reports each with an exact JSON Pointer, without mutating input.
/// </summary>
public static class PortablePolicySchema
{
    private static readonly JsonSchema Schema = BuildSchema();

    private static JsonSchema BuildSchema()
    {
        var generated = new JsonSchemaBuilder().FromType<PortablePolicy>().Build();
        var asNode = JsonSerializer.SerializeToNode(generated)!;
        StripRequired(asNode);
        return JsonSchema.FromText(asNode.ToJsonString());
    }

    /// <summary>Recursively drop every <c>required</c> keyword — presence is optional.</summary>
    private static void StripRequired(JsonNode? node)
    {
        switch (node)
        {
            case JsonObject obj:
                obj.Remove("required");
                foreach (var kv in obj.ToList())
                {
                    StripRequired(kv.Value);
                }

                break;
            case JsonArray arr:
                foreach (var item in arr)
                {
                    StripRequired(item);
                }

                break;
        }
    }

    /// <summary>The generated Draft 2020-12 schema as indented JSON (for publishing).</summary>
    public static string SchemaJson()
        => JsonSerializer.Serialize(Schema, new JsonSerializerOptions { WriteIndented = true });

    /// <summary>
    /// Validate a policy document against the generated schema. Returns an empty
    /// list when valid, otherwise one <see cref="PolicyValidationError"/> per
    /// failing location. Invalid JSON is a single root-level error. Never throws
    /// for bad input and never mutates state.
    /// </summary>
    public static IReadOnlyList<PolicyValidationError> Validate(string json)
    {
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(json ?? string.Empty);
        }
        catch (JsonException ex)
        {
            return new[] { new PolicyValidationError("", $"not valid JSON: {ex.Message}") };
        }

        using (document)
        {
            var results = Schema.Evaluate(document.RootElement, new EvaluationOptions
            {
                OutputFormat = OutputFormat.List,
            });

            if (results.IsValid)
            {
                return Array.Empty<PolicyValidationError>();
            }

            var errors = new List<PolicyValidationError>();
            Collect(results, errors);
            if (errors.Count == 0)
            {
                errors.Add(new PolicyValidationError("", "policy document did not match the schema"));
            }

            return errors;
        }
    }

    private static void Collect(EvaluationResults results, List<PolicyValidationError> errors)
    {
        if (results.Errors is { Count: > 0 } map)
        {
            var pointer = results.InstanceLocation.ToString();
            foreach (var message in map.Values)
            {
                errors.Add(new PolicyValidationError(pointer, message ?? "does not match the schema"));
            }
        }

        foreach (var detail in results.Details ?? Enumerable.Empty<EvaluationResults>())
        {
            Collect(detail, errors);
        }
    }
}
