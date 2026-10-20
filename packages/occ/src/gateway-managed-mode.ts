import type { AgentRevision } from "@openclaw-enterprise/contracts";
import { controllerWorkDeploymentStatus } from "./state/controller-work.ts";
import type { PlatformOperationReadRepository } from "./state/platform-state.ts";

export const GATEWAY_MANAGED_MODE_TRANSITION = "GATEWAY_MANAGED_MODE_TRANSITION";

type ActiveRevision = Pick<AgentRevision, "id" | "namespaceId" | "agentId" | "gatewayManagedMode">;
type DeploymentWork = Pick<PlatformOperationReadRepository, "findWork" | "findWorkAttempt">;

/** Whether this deployment must retain Installation administration until activation completes. */
export async function gatewayManagedModeDeploymentRequiresAdmin(
  requested: boolean | undefined,
  active: ActiveRevision | undefined,
  operations: DeploymentWork,
): Promise<boolean> {
  if (requested === undefined) {
    return false;
  }
  if (active === undefined) {
    return requested === false;
  }
  // A historical revision's unrecorded mode is unknown.
  if (requested !== active.gatewayManagedMode) {
    return true;
  }

  // Publishing the active pointer precedes activation. An unfinished mode-changing deployment
  // is not an established baseline, even if this deployment requests the same value.
  const workId = `agent_revision:${active.id}:reconcile`;
  const work = await operations.findWork(workId);
  if (
    work === undefined ||
    work.namespaceId !== active.namespaceId ||
    work.agentId !== active.agentId ||
    work.revisionId !== active.id
  ) {
    return true;
  }
  if (controllerWorkDeploymentStatus(work) === "succeeded") {
    return false;
  }
  return (await operations.findWorkAttempt(workId, GATEWAY_MANAGED_MODE_TRANSITION)) !== undefined;
}
