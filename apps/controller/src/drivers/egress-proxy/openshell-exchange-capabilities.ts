/** Ordered enforced profile. Earlier installation exchanges did not pin a complete response. */
export const openShellExchangeCapabilities = Object.freeze([
  "openshell.supervisor-middleware.http-credential-access.v1",
  "openshell.supervisor-middleware.installation-exchange.v1",
  "openshell.supervisor-middleware.response-custody.v1",
  "openshell.supervisor-middleware.execution-authority.v1",
  "openshell.supervisor-middleware.protected-no-material.v1",
]);

/** Other protocol capabilities may be advertised; this profile must occur exactly once in order. */
export function advertisesOpenShellExecutionProfile(value: unknown): boolean {
  if (!Array.isArray(value)) {
    return false;
  }
  const profile = value.filter((capability) => openShellExchangeCapabilities.includes(capability));
  return (
    profile.length === openShellExchangeCapabilities.length &&
    openShellExchangeCapabilities.every((capability, index) => profile[index] === capability)
  );
}
