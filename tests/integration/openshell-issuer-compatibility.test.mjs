import assert from "node:assert/strict";
import { spawn, execFileSync } from "node:child_process";
import { createHash, generateKeyPairSync, randomUUID, sign } from "node:crypto";
import { once } from "node:events";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import test from "node:test";
import { GrpcOpenShellGatewayClient } from "../../apps/controller/src/drivers/sandbox/openshell-gateway-client.ts";

const require = createRequire(new URL("../../apps/controller/package.json", import.meta.url));
const grpc = require("@grpc/grpc-js");
const loader = require("@grpc/proto-loader");
const binary = process.env.OCC_TEST_ISSUER_GATEWAY_BINARY;
const digest = "5764f256c7a6772832591f2b5478e7b5939bfd06cad148dfb6beb6c075785c2a";
const strategy = "PROVIDER_CREDENTIAL_REFRESH_STRATEGY_OAUTH2_CLIENT_CREDENTIALS";

test(
  "pinned OpenShell background refresh persists issuance without provider expiry",
  {
    skip:
      binary === undefined
        ? "select the pinned prebuilt gateway with OCC_TEST_ISSUER_GATEWAY_BINARY"
        : false,
    timeout: 60000,
  },
  async (t) => {
    assert.ok(isAbsolute(binary), "select an absolute binary path");
    assert.equal(
      createHash("sha256")
        .update(await readFile(binary))
        .digest("hex"),
      digest,
    );
    const directory = await mkdtemp(join(tmpdir(), "oce-issuer-probe-"));
    const cleanups = [() => rm(directory, { recursive: true, force: true })];
    t.after(async () => {
      const failures = [];
      for (const cleanup of cleanups.reverse()) {
        try {
          await cleanup();
        } catch (error) {
          failures.push(error);
        }
      }
      if (failures.length > 0) {
        throw new AggregateError(failures, "issuer probe cleanup failed");
      }
    });
    // Do not inherit provider credentials, proxies, telemetry, account config or
    // host compute selection. Every state/config path belongs to this test.
    const environment = {
      PATH: "/usr/bin:/bin",
      XDG_CONFIG_HOME: directory,
      XDG_STATE_HOME: directory,
      XDG_DATA_HOME: directory,
      XDG_CACHE_HOME: directory,
      TMPDIR: directory,
      OPENSHELL_TELEMETRY_ENABLED: "false",
    };
    const help = execFileSync(binary, ["--help"], { env: environment, encoding: "utf8" });
    assert.match(help, /--compute-driver-socket/);
    const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const jwk = {
      ...publicKey.export({ format: "jwk" }),
      kid: "fixture",
      alg: "RS256",
      use: "sig",
    };
    const clientId = randomUUID();
    const clientSecret = randomUUID();
    const requests = [];
    let mode = "refuse";
    let origin;
    const issuer = createServer(async (request, response) => {
      const reply = (status, body) => {
        response.writeHead(status, { "content-type": "application/json" });
        response.end(JSON.stringify(body));
      };
      if (request.method === "GET" && request.url === "/.well-known/openid-configuration") {
        reply(200, { issuer: origin, jwks_uri: `${origin}/jwks` });
        return;
      }
      if (request.method === "GET" && request.url === "/jwks") {
        reply(200, { keys: [jwk] });
        return;
      }
      if (request.method !== "POST" || request.url !== "/token") {
        reply(404, {});
        return;
      }
      const chunks = [];
      for await (const chunk of request) {
        chunks.push(chunk);
      }
      const form = new URLSearchParams(Buffer.concat(chunks).toString());
      const authenticated =
        form.get("client_id") === clientId && form.get("client_secret") === clientSecret;
      // Record names and authentication outcome, never credentials. This fixture
      // has no admitted OCE attempt and therefore must not mint a real candidate.
      requests.push({
        keys: [...form.keys()].sort(),
        headers: Object.keys(request.headers).sort(),
        contentType: request.headers["content-type"],
        authenticated,
        grant: form.get("grant_type"),
        scope: form.get("scope"),
      });
      if (!authenticated) {
        reply(401, { error: "invalid_client" });
      } else if (mode === "refuse") {
        reply(400, { error: "access_denied" });
      } else {
        // Deliberately invalid as OCE issuance: no actual expiry, returned rights,
        // owner epoch, attempt or material version. It tests Rust acceptance only.
        reply(200, { access_token: `SYNTHETIC-${randomUUID()}` });
      }
    });
    issuer.listen(0, "127.0.0.1");
    await once(issuer, "listening");
    origin = `http://127.0.0.1:${issuer.address().port}`;
    cleanups.push(() => new Promise((resolve) => issuer.close(resolve)));

    const definition = await loader.load(
      join(import.meta.dirname, "../fixtures/issuer-probe-compute.proto"),
      { keepCase: true },
    );
    const compute = new grpc.Server();
    const watches = new Set();
    const capability = "openshell.compute.contract";
    compute.addService(
      grpc.loadPackageDefinition(definition).openshell.compute.v1.ComputeDriver.service,
      {
        GetCapabilities(_call, callback) {
          callback(null, {
            driver_name: "issuer-probe",
            extension: {
              protocol_version: { major: 1 },
              implementation_name: "fixture/issuer-probe",
              implementation_version: "1",
              supported_capabilities: [capability],
              required_capabilities: [capability],
            },
            resource_admission_policy: `v1:${JSON.stringify({ allow_driver_config: false, resource_admission: { enabled: true, required_labels: { "openshell.ai/sandbox-attachable": "true", "openshell.ai/sandbox-attachable-workspace": "${workspace}" } } })}`,
          });
        },
        ListSandboxes(_call, callback) {
          callback(null, {});
        },
        WatchSandboxes(call) {
          watches.add(call);
          call.on("cancelled", () => watches.delete(call));
        },
      },
    );
    const socket = join(directory, "compute.sock");
    await new Promise((resolve, reject) =>
      compute.bindAsync(`unix:${socket}`, grpc.ServerCredentials.createInsecure(), (error) =>
        error ? reject(error) : resolve(),
      ),
    );
    cleanups.push(() => {
      for (const call of watches) {
        call.end();
      }
      compute.forceShutdown();
    });
    const config = join(directory, "gateway.toml");
    const gatewayKey = generateKeyPairSync("ed25519");
    await writeFile(
      join(directory, "signing.pem"),
      gatewayKey.privateKey.export({ type: "pkcs8", format: "pem" }),
      { mode: 0o600 },
    );
    await writeFile(
      join(directory, "public.pem"),
      gatewayKey.publicKey.export({ type: "spki", format: "pem" }),
    );
    await writeFile(join(directory, "kid"), "fixture");
    await writeFile(
      config,
      `[openshell]
version = 2
[openshell.gateway.gateway_jwt]
signing_key_path = "${join(directory, "signing.pem")}"
public_key_path = "${join(directory, "public.pem")}"
kid_path = "${join(directory, "kid")}"
[openshell.drivers.issuer-probe]
`,
    );
    const jwtPart = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
    const jwtBody = `${jwtPart({ alg: "RS256", kid: "fixture" })}.${jwtPart({ iss: origin, sub: "issuer-probe", aud: "openshell-cli", exp: Math.floor(Date.now() / 1000) + 600, realm_access: { roles: ["openshell-admin"] } })}`;
    const bearerFile = join(directory, "bearer");
    await writeFile(
      bearerFile,
      `${jwtBody}.${sign("RSA-SHA256", Buffer.from(jwtBody), privateKey).toString("base64url")}`,
      { mode: 0o600 },
    );
    let child;
    let client;
    async function stop() {
      client?.close();
      if (child && child.exitCode === null && child.signalCode === null) {
        const exited = once(child, "exit");
        child.kill("SIGTERM");
        const timer = setTimeout(() => child.kill("SIGKILL"), 3000);
        await exited;
        clearTimeout(timer);
      }
    }
    cleanups.push(stop);
    async function start() {
      const portReservation = createServer();
      portReservation.listen(0, "127.0.0.1");
      await once(portReservation, "listening");
      const port = portReservation.address().port;
      await new Promise((resolve) => portReservation.close(resolve));
      child = spawn(
        binary,
        [
          "--config",
          config,
          "--bind-address",
          "127.0.0.1",
          "--port",
          String(port),
          "--disable-tls",
          "--db-url",
          `sqlite://${join(directory, "gateway.sqlite")}`,
          "--compute-driver",
          "issuer-probe",
          "--compute-driver-socket",
          socket,
          "--oidc-issuer",
          origin,
          "--oidc-dangerously-allow-insecure-http",
          "true",
        ],
        { env: environment, cwd: directory, stdio: ["ignore", "pipe", "pipe"] },
      );
      let output = "";
      for (const stream of [child.stdout, child.stderr]) {
        stream.on("data", (chunk) => {
          output = (output + chunk).slice(-12000);
        });
      }
      client = new GrpcOpenShellGatewayClient({
        endpoint: `http://127.0.0.1:${port}`,
        auth: { mode: "bearerTokenFile", path: bearerFile },
        requestTimeoutMs: 1000,
      });
      for (let attempt = 0; attempt < 100; attempt += 1) {
        assert.equal(child.exitCode, null, `gateway startup failed: ${output}`);
        try {
          await client.health(AbortSignal.timeout(1000));
          return;
        } catch {
          await delay(50);
        }
      }
      assert.fail(`gateway did not become healthy: ${output}`);
    }
    await start();
    const signal = () => AbortSignal.timeout(5000);
    const workspace = "issuer-probe";
    await client.createWorkspace(workspace, {}, signal());
    await client.importProviderProfile(
      workspace,
      {
        id: "issuer-probe",
        displayName: "Issuer compatibility probe",
        category: "PROVIDER_PROFILE_CATEGORY_OTHER",
        credentials: [
          {
            name: "access_token",
            envVars: ["PROBE_TOKEN"],
            required: true,
            authStyle: "bearer",
            headerName: "authorization",
            refresh: {
              strategy,
              tokenUrl: `${origin}/token`,
              scopes: ["repository:read"],
              material: [
                { name: "client_id", required: true, secret: false },
                { name: "client_secret", required: true, secret: true },
              ],
            },
          },
        ],
        endpoints: [],
        binaries: [],
        inferenceCapable: false,
        annotations: {},
      },
      signal(),
    );
    await client.createProvider(
      {
        workspace,
        name: "probe",
        type: "issuer-probe",
        labels: {},
        credentials: { PROBE_TOKEN: `SYNTHETIC-${randomUUID()}` },
        credentialExpirationTimes: { PROBE_TOKEN: new Date(Date.now() + 7200000).toISOString() },
      },
      signal(),
    );
    assert.equal(
      await client.getProviderRefreshStatus(workspace, "probe", "PROBE_TOKEN", signal()),
      undefined,
    );
    assert.equal(requests.length, 0, "a status read must not invoke the issuer");
    const configure = () =>
      client.configureProviderRefresh(
        {
          workspace,
          provider: "probe",
          credentialKey: "PROBE_TOKEN",
          strategy,
          material: { client_id: clientId, client_secret: clientSecret },
          requestId: randomUUID(),
        },
        signal(),
      );
    await configure();
    await assert.rejects(
      client.rotateProviderCredential(workspace, "probe", "PROBE_TOKEN", randomUUID(), signal()),
    );
    const refused = await client.getProviderRefreshStatus(
      workspace,
      "probe",
      "PROBE_TOKEN",
      signal(),
    );
    assert.equal(refused.status, "configuration_required");
    assert.equal(refused.failureCode, "oauth_access_denied");
    assert.deepEqual(requests, [
      {
        keys: ["client_id", "client_secret", "grant_type", "scope"],
        headers: ["accept", "content-length", "content-type", "host"],
        contentType: "application/x-www-form-urlencoded",
        authenticated: true,
        grant: "client_credentials",
        scope: "repository:read",
      },
    ]);
    await stop();
    await start();
    assert.deepEqual(
      await client.getProviderRefreshStatus(workspace, "probe", "PROBE_TOKEN", signal()),
      refused,
      "refusal must survive restart",
    );
    assert.equal(requests.length, 1);
    // Re-admit a due refresh, then let the real startup sweep run it. We never
    // call Rotate in this phase. A provider version change and a second restart
    // distinguish a persisted result from a request observed only at the issuer.
    await configure();
    const readStatus = () =>
      client.getProviderRefreshStatus(workspace, "probe", "PROBE_TOKEN", signal());
    const providerVersion = async () =>
      (await client.getProvider(workspace, "probe", signal())).resourceVersion;
    const priorVersion = await providerVersion();
    await stop();
    mode = "incomplete";
    const before = Date.now();
    await start();
    let accepted;
    let publishedVersion;
    for (let attempt = 0; attempt < 50; attempt += 1) {
      accepted = await readStatus();
      publishedVersion = await providerVersion();
      if (accepted?.status === "refreshed" && publishedVersion !== priorVersion) {
        break;
      }
      await delay(50);
    }
    assert.equal(accepted?.status, "refreshed", "background refresh completed");
    assert.ok(BigInt(publishedVersion) > BigInt(priorVersion), "provider publication observed");
    assert.equal(requests.length, 2, "exactly one background exchange");
    assert.deepEqual(requests[1], requests[0], "new attempt was indistinguishable to the issuer");
    assert.ok(
      Date.parse(accepted.expirationTime) >= before + 3599000,
      "Rust substitutes its default one-hour lifetime for missing provider expiry",
    );
    assert.ok(Date.parse(accepted.expirationTime) <= Date.now() + 3601000);
    await stop();
    await start();
    assert.deepEqual(await readStatus(), accepted, "synthetic expiry must survive restart");
    assert.equal(await providerVersion(), publishedVersion, "provider version survived restart");
    assert.equal(requests.length, 2, "restart/status observation must not mint again");
    t.diagnostic(
      "Compatibility remains unqualified: no admitted-attempt mapping is exercised; Rust persists an invented expiry for incomplete issuance. No OCE readiness is established.",
    );
  },
);
