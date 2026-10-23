// Shared Installation value validation. File loading, environment access and
// Driver binding remain in their owning composition modules.
import { asRecord, isNonEmptyString } from "@openclaw-enterprise/utils";
import { isAbsolute } from "node:path";

export type ConfigurationRecord = Readonly<Record<string, unknown>>;

export function object(value: unknown, path: string): ConfigurationRecord {
  const result = asRecord(value);
  if (result === undefined) {
    throw new Error(`${path} must be one object.`);
  }
  return result;
}

export function closed(value: ConfigurationRecord, keys: readonly string[], path: string): void {
  for (const key of Object.keys(value)) {
    if (!keys.includes(key)) {
      throw new Error(`${path} contains unsupported option ${key}.`);
    }
  }
}

export function nonempty(value: unknown, path: string): string {
  if (!isNonEmptyString(value)) {
    throw new Error(`${path} must be a nonempty string.`);
  }
  return value;
}

export interface EgressAuthorityConfiguration {
  readonly host: string;
  readonly port: number;
  readonly certificatePath: string;
  readonly privateKeyPath: string;
  readonly issuerPublicKeyPath: string;
  readonly issuer: string;
  readonly audience: string;
  readonly keyId: string;
}

export function egressAuthorityConfiguration(
  input: unknown,
  mode: "development" | "production",
): EgressAuthorityConfiguration {
  const value = asRecord(input);
  const fields = [
    "host",
    "port",
    "certificatePath",
    "privateKeyPath",
    "issuerPublicKeyPath",
    "issuer",
    "audience",
    "keyId",
  ];
  if (
    !value ||
    Object.keys(value).some((key) => !fields.includes(key)) ||
    fields.some((key) => key !== "port" && (typeof value[key] !== "string" || !value[key])) ||
    !Number.isSafeInteger(value.port) ||
    Number(value.port) < 1 ||
    Number(value.port) > 65535 ||
    !["certificatePath", "privateKeyPath", "issuerPublicKeyPath"].every((key) =>
      isAbsolute(String(value[key])),
    ) ||
    (mode === "development" && !["127.0.0.1", "::1"].includes(String(value.host)))
  ) {
    throw new Error(
      "Protected egress requires explicit TLS, issuer identity and a loopback development listener.",
    );
  }
  return value as unknown as EgressAuthorityConfiguration;
}

/**
 * An Installation listener that the production chart's Service cannot reach: the chart
 * serves no such listener, serves it on another port, or the listener does not bind all
 * addresses. Startup and the chart's upgrade check report it as `CHART_LISTENER_MISMATCH`.
 * The message names the Installation and Helm settings and values, which hold no secret;
 * `path` is the refused Installation setting as a JSON Pointer (finding 2213).
 */
export class ChartListenerMismatchError extends Error {
  override readonly name = "ChartListenerMismatchError";
  readonly code = "CHART_LISTENER_MISMATCH";
  readonly path: string;
  constructor(message: string, setting: string) {
    super(message);
    this.path = setting === "" ? "" : `/${setting.replaceAll(".", "/")}`;
  }
}

/** The chart routes these listeners and passes each one's port, or `disabled`, to startup. */
export const chartListeners = {
  egressAuthority: {
    path: "drivers.credential_proxy.configuration.authority",
    chart: "egressAuthority",
    variable: "OCC_EGRESS_AUTHORITY_PORT",
  },
  openshellGit: {
    path: "repository.openShell.authority",
    chart: "openshellGit",
    variable: "OCC_OPENSHELL_GIT_PORT",
  },
} as const;

/**
 * Refuse an Installation listener the chart's Service cannot reach. The Service targets the
 * Pod's address, which the Installation cannot name, so the listener must bind all addresses.
 * Without the chart's variable (no chart, for example a test or another packaging) there is
 * nothing to compare.
 */
export function requireChartListener(
  authority: Pick<EgressAuthorityConfiguration, "host" | "port"> | undefined,
  environment: Readonly<Record<string, string | undefined>>,
  listener: (typeof chartListeners)[keyof typeof chartListeners],
): void {
  const declared = environment[listener.variable];
  if (declared === undefined) {
    return;
  }
  if (declared === "disabled") {
    if (authority !== undefined) {
      throw new ChartListenerMismatchError(
        `${listener.path}.port is ${authority.port}, but Helm ${listener.chart}.enabled is false, so no chart Service reaches it.`,
        `${listener.path}.port`,
      );
    }
    return;
  }
  const port = /^[1-9][0-9]{0,4}$/.test(declared) ? Number(declared) : 0;
  if (port < 1 || port > 65535) {
    throw new ChartListenerMismatchError(
      `${listener.variable} must be a TCP port from 1 to 65535 or disabled.`,
      "",
    );
  }
  if (authority === undefined) {
    return;
  }
  if (authority.port !== port) {
    throw new ChartListenerMismatchError(
      `${listener.path}.port is ${authority.port}, but Helm ${listener.chart}.port is ${port}.`,
      `${listener.path}.port`,
    );
  }
  if (authority.host !== "0.0.0.0" && authority.host !== "::") {
    throw new ChartListenerMismatchError(
      `${listener.path}.host is ${authority.host}, but the chart's ${listener.chart} Service on port ${port} reaches only a listener on all addresses: use 0.0.0.0 or ::.`,
      `${listener.path}.host`,
    );
  }
}

export function openShellRepositoryConfiguration(
  input: unknown,
  mode: "development" | "production",
) {
  if (input === undefined) {
    return undefined;
  }
  const value = object(input, "repository.openShell");
  closed(value, ["registrationName", "authority"], "repository.openShell");
  return {
    registrationName: nonempty(value.registrationName, "repository.openShell.registrationName"),
    authority: egressAuthorityConfiguration(value.authority, mode),
  };
}
