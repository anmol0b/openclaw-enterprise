import assert from "node:assert/strict";
import { generateKeyPairSync, randomBytes, verify } from "node:crypto";
import { readFile } from "node:fs/promises";
import { createServer } from "node:https";

export const repository = { id: 7301, full_name: "fixture/repository" };
export const repositoryPath = "/repos/" + repository.full_name;

// Only GitHub's public wire is simulated. Production OCE must prepare the token
// and constrain its use; this listener counts even unauthorized business traffic.
export async function startCustodyRepositoryOrigin(t, configuration) {
  const identity = {
    app_id: "7302",
    installation_id: "7303",
    repository_id: "7301",
    repository: repository.full_name,
  };
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const token = "synthetic-custody-" + randomBytes(32).toString("hex");
  const issuerKey = privateKey.export({ format: "pem", type: "pkcs8" }).toString();
  configuration.protect?.(token, issuerKey);
  const observations = [];
  let mode = "normal";
  let issues = 0;
  let tcp = 0;
  let hold;
  let release;
  const server = createServer(
    {
      cert: await readFile(configuration.certificatePath),
      key: await readFile(configuration.privateKeyPath),
    },
    async (req, res) => {
      const body = [];
      for await (const chunk of req) {
        body.push(chunk);
      }
      const text = Buffer.concat(body).toString();
      if (req.method === "POST" && req.url === "/app/installations/7303/access_tokens") {
        try {
          const [header, claims, signature] = (req.headers.authorization ?? "")
            .replace(/^Bearer /i, "")
            .split(".");
          assert.ok(
            verify(
              "RSA-SHA256",
              header + "." + claims,
              publicKey,
              Buffer.from(signature, "base64url"),
            ),
          );
          assert.equal(String(JSON.parse(Buffer.from(claims, "base64url")).iss), identity.app_id);
          assert.deepEqual(JSON.parse(text), {
            repository_ids: [repository.id],
            permissions: { metadata: "read" },
          });
        } catch {
          res.writeHead(403).end();
          return;
        }
        issues++;
        res.writeHead(201, { "content-type": "application/json" }).end(
          JSON.stringify({
            token,
            permissions: { metadata: "read" },
            repositories: [repository],
            expires_at: new Date(Date.now() + 55 * 60_000).toISOString(),
          }),
        );
        return;
      }
      if (
        req.method === "DELETE" &&
        req.url === "/installation/token" &&
        req.headers.authorization === "Bearer " + token
      ) {
        res.writeHead(204).end();
        return;
      }
      const selected = mode;
      const entry = {
        number: observations.length + 1,
        mode: selected,
        exactRead:
          issues > 0 &&
          req.method === "GET" &&
          req.url === repositoryPath &&
          !text &&
          req.headers.authorization === "Bearer " + token,
        finished: false,
        closed: false,
      };
      observations.push(entry);
      res.once("close", () => {
        entry.closed = true;
      });
      if (!entry.exactRead) {
        res.writeHead(403).end();
        return;
      }
      if (selected === "hold") {
        await new Promise((resolve) => {
          release = resolve;
          hold();
        });
      }
      // Body and unapproved header precede the *last actual* forbidden trailer.
      // Record finish after both went to the TLS socket, never infer application.
      const responseBody = JSON.stringify({ ...repository, description: "omit-from-response" });
      if (selected === "forbidden-final") {
        const finalName = "x-fixture-forbidden-last";
        const wire = [
          "HTTP/1.1 200 OK",
          "Content-Type: application/json",
          "Connection: close",
          "Transfer-Encoding: chunked",
          "",
          responseBody.length.toString(16),
          responseBody,
          "0",
          "x-fixture-first: allowed-shape",
          finalName + ": " + token,
          "",
          "",
        ].join("\r\n");
        res.socket.end(wire, () => {
          entry.actualLastTrailer = finalName;
          entry.finished = true;
        });
        return;
      }
      res.once("finish", () => {
        entry.finished = true;
      });
      res.writeHead(200, {
        "content-type": "application/json",
        "x-fixture-private": "omit-from-response",
      });
      res.end(responseBody);
    },
  );
  server.on("connection", () => {
    tcp++;
  });
  t.after(
    () =>
      new Promise((resolve) => {
        release?.();
        server.close(resolve);
        server.closeAllConnections();
      }),
  );
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(configuration.bindPort, configuration.bindHost, resolve);
  });
  return {
    observations,
    identity,
    businessOrigin: new URL(configuration.origin).origin,
    privateKey: issuerKey,
    forbiddenFinal() {
      mode = "forbidden-final";
    },
    normal() {
      mode = "normal";
    },
    holdNext() {
      mode = "hold";
      return new Promise((resolve) => {
        hold = resolve;
      });
    },
    release() {
      release();
      mode = "normal";
    },
    get issues() {
      return issues;
    },
    get tcpConnections() {
      return tcp;
    },
  };
}
