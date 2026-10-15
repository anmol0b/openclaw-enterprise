import assert from "node:assert/strict";
import { createConnection } from "node:net";
import { repository, repositoryPath } from "../fixtures/egress-custody-repository-origin.mjs";

export const refusal = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

export function faultObserver(socket, command = "status") {
  return new Promise((resolve, reject) => {
    let reply = "";
    const connection = createConnection(socket, () => connection.end(command));
    connection.setTimeout(3000, () =>
      connection.destroy(new Error("missing dispatch fault observer")),
    );
    connection.on("error", reject).on("data", (data) => {
      reply += data;
    });
    connection.on("end", () => {
      try {
        const status = JSON.parse(reply);
        assert.equal(typeof status.authorizations, "number", "observer must confirm selection");
        resolve(status);
      } catch (error) {
        reject(error);
      }
    });
  });
}

// Read the complete selected supervisor log. A truncated/missing log or a previous
// container cannot masquerade as no permits; the refusal event is affirmative.
export async function supplierEvents(setup, placement, supervisor) {
  const pod = await setup.f.resource("pod", supervisor.metadata.name, placement);
  assert.equal(pod.metadata.uid, supervisor.metadata.uid);
  const [container] = pod.status.containerStatuses;
  assert.equal(container.restartCount, 0);
  const log = await setup.f.kubectl(
    "logs",
    pod.metadata.name,
    "-n",
    placement,
    "-c",
    container.name,
  );
  const events = [];
  for (const line of log.split("\n")) {
    if (!line.includes("response_custody_event")) {
      continue;
    }
    const [, event] = /response_custody_event[" :=]+([a-z_]+)\b/.exec(line) ?? [];
    const [, id] =
      /request_id[" :=]+([a-f0-9]{8}-[a-f0-9]{4}-7[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12})\b/.exec(
        line,
      ) ?? [];
    assert.ok(event && id, "supplier reported an unjoinable custody transition");
    events.push({ event, id });
  }
  return events;
}

export function exactTransitions(events, before, expected) {
  assert.deepEqual(events.slice(0, before.length), before, "complete supplier log continuity");
  const fresh = events.slice(before.length);
  const ids = new Set(fresh.map(({ id }) => id));
  assert.equal(ids.size, 1, "one actual supplier operation, no retry or ambiguous observation");
  assert.deepEqual(
    fresh.map(({ event }) => event),
    expected,
  );
  return fresh[0].id;
}

// Deliberately project truth predicates, never return a proof, custody nonce,
// credential, or provider response. use_id joins the real supplier request ID.
export async function receipts(pool, installation, selection = "prepared_github") {
  const {
    enforcement: { instanceId, peerKeyId },
    sandboxId,
    plan: { execution },
  } = installation;
  const rows = (
    await pool.query(
      `
    WITH actual AS (
      SELECT use_id AS id, observation, outcome, settled, binding,
        authorized_dispatch AS dispatch, authorized_dispatch->'association' AS a
      FROM occ.egress_send_receipts WHERE instance_id=$1
    )
    SELECT id, observation, outcome, settled,
      (a->'execution'=$2::jsonb AND a->'installation'->>'sandboxId'=$3 AND
       a->'installation'->>'instanceId'=$1 AND a->'installation'->>'peerKeyId'=$4 AND
       length(a->>'exchangeId') > 0 AND length(a->>'responseId') > 0 AND length(a->>'custodyId') > 0 AND
       count(*) over (partition by a->>'custodyId')=1 AND
       a->'installation'->>'authorityScope'='execution' AND a->'installation'->>'policyHash'=$6 AND
       binding->'material'->>'kind'=$5 AND CASE WHEN $5='no_material_required' THEN
       (binding->'material') - ARRAY['kind','source','binding','grantHash','isolationId'] = '{}'::jsonb AND
       binding #>> '{material,source,provider,id}' = 'credential-free-repository-metadata' AND
       dispatch->>'injectionDigest' = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
       ELSE
       (binding->'material'->>'ownerEpoch')::bigint > 0 AND
       (binding->'material'->'family'->>'generation')::bigint > 0 END AND length(dispatch->>'requestDigest')=64 AND
       length(dispatch->>'injectionDigest')=64 AND
       (dispatch->>'sendStartBy')::timestamptz <= (binding->>'deadlineAt')::timestamptz) AS exact
    FROM actual ORDER BY id`,
      [instanceId, execution, sandboxId, peerKeyId, selection, installation.enforcement.policyHash],
    )
  ).rows;
  return rows;
}

export function agentClients(setup, stack, harness, origin, path = repositoryPath) {
  const target = origin + path;
  const inAgent = (...args) =>
    setup.f.kubectl(
      "exec",
      "-n",
      stack.placement,
      harness.metadata.name,
      "-c",
      "agent",
      "--",
      ...args,
    );
  // Ordinary independent clients. Neither conveys an identity, credential, binding,
  // executable assertion or capture hook. Both must receive exactly the selected identity.
  const curl = () =>
    inAgent(
      "curl",
      "--silent",
      "--show-error",
      "--include",
      "--raw",
      "--max-time",
      "28",
      "--header",
      "Connection: close",
      target,
    );
  const node = () =>
    inAgent(
      "node",
      "-e",
      `
    const https=require("node:https");
    const req=https.get(process.argv[1], {headers:{connection:"close"}}, res => {
      const authorized = res.socket.authorized; let body=""; res.on("data",c=>body+=c); res.on("end",()=> {
        if (!res.complete || Object.keys(res.trailers).length || !authorized) process.exitCode=3;
        process.stdout.write(JSON.stringify({status:res.statusCode,body}));
      });
    }); req.on("error",()=>{process.exitCode=4}); req.setTimeout(28000,()=>req.destroy());
  `,
      target,
    );
  return { curl, node, inAgent };
}

export function assertIdentityResponse(raw, expected = repository) {
  const identity = JSON.stringify(expected);
  const [headers, body, ...extra] = raw.split("\r\n\r\n");
  const [status, ...fields] = headers.split("\r\n");
  assert.ok(status === "HTTP/1.1 200 OK", "expected approved provider status");
  assert.deepEqual(
    fields.map((value) => value.toLowerCase()).sort(),
    [
      "cache-control: no-store",
      "connection: close",
      "content-length: " + Buffer.byteLength(identity),
      "content-type: application/json",
    ].sort(),
  );
  assert.ok(body === identity && extra.length === 0, "complete exact approved bytes only");
}

// Bypass the protected HTTP transport entirely. Connect by IP to the *same* live,
// permitted TCP target. Even a connection that wrote no HTTP would fail this test.
export async function tryDirectTcp(provider, configuration, inAgent) {
  const { bindHost: host, bindPort: port } = configuration;
  const control = () =>
    new Promise((resolve, reject) => {
      const peer = createConnection({ host, port }, () => peer.end());
      peer.setTimeout(3000, () => peer.destroy(new Error("observer positive control unreachable")));
      peer.on("error", reject).on("close", resolve);
    });
  const start = provider.tcpConnections;
  await control();
  assert.equal(
    provider.tcpConnections,
    start + 1,
    "independent positive reachability of exact bypass target",
  );
  const outcome = JSON.parse(
    await inAgent(
      "node",
      "-e",
      `
    const net=require("node:net");
    const socket=net.connect({host:process.argv[1], port:Number(process.argv[2])});
    let outcome="no-observation"; socket.setTimeout(4000,()=>{outcome="timed-out";socket.destroy()});
    socket.on("error", (e)=>{outcome=e.code||"unclassified-error"});
    socket.on("connect", ()=>socket.write("OCE unmanaged bypass probe\\r\\n"));
    socket.on("data", ()=>{outcome="local-reply";socket.destroy()});
    socket.on("end", ()=>{outcome="peer-refused"});
    socket.on("close", ()=>process.stdout.write(JSON.stringify(outcome)));
  `,
      host,
      String(port),
    ),
  );
  assert.ok(
    ["timed-out", "ECONNREFUSED", "ECONNRESET", "EACCES", "peer-refused", "local-reply"].includes(
      outcome,
    ),
    "workload must execute actual direct connection attempt",
  );
  await control();
  assert.equal(
    provider.tcpConnections,
    start + 2,
    "direct workload bypass reached the independently observed permitted TCP target",
  );
  return { directWorkloadOutcome: outcome, observerControls: 2, directWorkloadConnections: 0 };
}
