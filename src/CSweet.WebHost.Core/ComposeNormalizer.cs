using System.Text.Json;
using System.Text.Json.Nodes;
using CSweet.WebHost.Contracts;

namespace CSweet.WebHost.Core;

/// <summary>Produces the only Compose document the product guest may execute.
/// Docker never receives the repository's unfiltered configuration.</summary>
public static class ComposeNormalizer
{
    public static string Normalize(PreviewManifest manifest, Guid workloadId, IReadOnlyDictionary<string, string> builtImages)
    {
        var errors = ManifestValidator.Validate(manifest);
        if (errors.Count > 0) throw new PreviewPolicyException(errors);
        if (manifest.Mode != PreviewMode.Containers || workloadId == Guid.Empty)
            throw new ArgumentException("Container normalization requires an exact workload.");
        var output = JsonNode.Parse(manifest.Compose.GetRawText())!.AsObject();
        var services = output["services"]!.AsObject();
        long replicas = 0;
        foreach (var pair in services)
            replicas = checked(replicas + (pair.Value!.AsObject()["scale"]?.GetValue<int>() ?? 1));
        // Capacity determines usable topology; service count itself is not capped.
        var memoryPerReplica = manifest.Resources.MemoryMb / replicas;
        var processesPerReplica = manifest.Resources.MaximumProcesses / replicas;
        if (memoryPerReplica < 16 || processesPerReplica < 1)
            throw new InvalidOperationException("Request more memory/process capacity for this stack.");
        foreach (var pair in services)
        {
            var service = pair.Value!.AsObject();
            if (service.ContainsKey("build"))
            {
                if (!builtImages.TryGetValue(pair.Key, out var image) || image.Length != 71 ||
                    !CSweet.Isolation.Security.WorkloadAuthorizationEnvelope.IsDigest(image))
                    throw new InvalidDataException("Every built service must resolve to a verified local image ID.");
                service.Remove("build");
                service["image"] = image;
            }
            service["pull_policy"] = "never";
            service["read_only"] = true;
            service["cap_drop"] = new JsonArray("ALL");
            service["security_opt"] = new JsonArray("no-new-privileges:true");
            service["tmpfs"] = new JsonArray("/tmp:rw,nosuid,nodev,size=67108864");
            service["pids_limit"] = processesPerReplica;
            service["mem_limit"] = checked(memoryPerReplica * 1024 * 1024);
            service["cpus"] = Math.Max(0.001, (double)manifest.Resources.CpuCount / replicas);
            service["restart"] = "no";
            service["init"] = true;
            service["networks"] = new JsonArray("product");
            if (pair.Key == manifest.Entrypoint!.Service)
            {
                if ((service["scale"]?.GetValue<int>() ?? 1) != 1)
                    throw new InvalidOperationException("The browser entry service must be a single gateway; place replicas behind it.");
                // This port is inside the guest only. The certified guest relay owns access to it.
                service["ports"] = new JsonArray(new JsonObject
                { ["target"] = manifest.Entrypoint.Port, ["published"] = "18080", ["host_ip"] = "127.0.0.1", ["protocol"] = "tcp" });
            }
        }
        output["name"] = "preview-" + workloadId.ToString("N");
        output["networks"] = new JsonObject { ["product"] = new JsonObject { ["internal"] = true } };
        return output.ToJsonString(PreviewJson.Options);
    }
}
