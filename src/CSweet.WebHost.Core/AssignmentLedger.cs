using CSweet.Isolation.Security;
using CSweet.WebHost.Contracts;

namespace CSweet.WebHost.Core;

public sealed class AssignmentLedger(DurableState state, AssignmentVerifier verifier)
{
    /// <returns>False for an exact retry. A caller must never launch a second VM on that result.</returns>
    public async Task<bool> ClaimAsync(SignedProductAssignment assignment, CancellationToken token = default)
    {
        verifier.Verify(assignment);
        var digest = WorkloadAuthorizationEnvelope.Digest(Convert.ToBase64String(assignment.Payload()));
        return await state.TransactionAsync(data =>
        {
            if (data.StoppedWorkloads.Contains(assignment.WorkloadId))
                throw new UnauthorizedAccessException("A stopped workload cannot be launched or replayed.");
            if (data.Assignments.TryGetValue(assignment.AssignmentId, out var existing))
            {
                if (existing.PayloadDigest == digest) return false;
                throw new UnauthorizedAccessException("Assignment replay conflicts with protected execution history.");
            }
            if (data.WorkloadAssignments.ContainsKey(assignment.WorkloadId))
                throw new UnauthorizedAccessException("A workload identity cannot be reassigned.");
            data.Assignments.Add(assignment.AssignmentId, new(assignment.AssignmentId, assignment.WorkloadId,
                assignment.FencingEpoch, digest, assignment.ExpiresAt, "Claimed"));
            data.WorkloadAssignments.Add(assignment.WorkloadId, assignment.AssignmentId);
            return true;
        }, token);
    }
}
