import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  createKubernetesClient,
  validateExplicitK3dLoopbackContext,
} from "../helpers/kubernetes-real.mjs";
import { parseProductionChart, renderProductionChart } from "../helpers/production-chart.mjs";

type ChartResource = {
  kind?: string;
  metadata?: { name?: string; namespace?: string };
  spec?: { managedBy?: string };
};

const selection = {
  kubeconfigPath: process.env.OCC_TEST_KUBERNETES_KUBECONFIG,
  kubernetesContext: process.env.OCC_TEST_KUBERNETES_CONTEXT,
};
const skip =
  selection.kubeconfigPath || selection.kubernetesContext
    ? false
    : "requires explicit disposable k3d";
test(
  "installation handoff distinguishes replaced Helm Jobs with only named get access",
  { skip },
  async (t) => {
    await validateExplicitK3dLoopbackContext(selection);
    const { kubectl, applyManifest } = createKubernetesClient({ selection });
    const dir = await mkdtemp(join(tmpdir(), "occ-handoff-"));
    t.after(() => rm(dir, { recursive: true, force: true }));
    const occ = join(dir, "occ");
    execFileSync("go", ["build", "-o", occ, "./cmd/occ"]);

    const namespace = `handoff-${randomUUID()}`;
    const name = "oce-initialization";
    await kubectl("create", "namespace", namespace);
    t.after(() => kubectl("delete", "namespace", namespace, "--wait=false"));
    const admin = (...args: string[]) => kubectl("-n", namespace, ...args);

    // Start with a new service account and no binding. Build its kubeconfig
    // from public cluster connection details only; never copy the admin user.
    await admin("create", "serviceaccount", "reader");
    const token = (await admin("create", "token", "reader", "--duration=10m")).trim();
    const clusters: unknown = JSON.parse(
      await kubectl(
        "config",
        "view",
        "--minify",
        "--flatten",
        "--raw",
        "-o",
        "jsonpath-as-json={.clusters[*]}",
      ),
    );
    assert.ok(Array.isArray(clusters));
    const cluster: unknown = clusters[0];
    assert.ok(cluster && typeof cluster === "object" && "name" in cluster);
    assert.ok(typeof cluster.name === "string");
    const config = join(dir, "reader.json");
    await writeFile(
      config,
      JSON.stringify({
        apiVersion: "v1",
        kind: "Config",
        clusters,
        contexts: [{ name: "read", context: { cluster: cluster.name, user: "reader" } }],
        users: [{ name: "reader", user: { token } }],
      }),
      { mode: 0o600 },
    );

    function handoff(
      action: "doctor" | "plan",
      status: number,
      expected: RegExp,
      ...args: string[]
    ) {
      const result = spawnSync(
        occ,
        [
          "installation",
          action,
          "--kubeconfig",
          config,
          "--context",
          "read",
          "--kube-namespace",
          namespace,
          "--release",
          "oce",
          ...args,
        ],
        { encoding: "utf8" },
      );
      assert.equal(result.status, status, result.stderr + result.stdout);
      assert.match(result.stdout, expected);
    }
    handoff("doctor", 1, /unknown. Could not read/);
    await admin(
      "create",
      "role",
      "reader",
      "--verb=get",
      "--resource=jobs.batch",
      `--resource-name=${name}`,
    );
    await admin(
      "create",
      "rolebinding",
      "reader",
      "--role=reader",
      `--serviceaccount=${namespace}:reader`,
    );
    handoff("doctor", 1, /not found at the selected target/);

    async function retainedJob(isUpgrade: boolean) {
      const { stdout } = await renderProductionChart({}, { namespace, isUpgrade });
      const resources: ChartResource[] = await parseProductionChart(stdout);
      const job = resources.find(
        (resource) => resource.kind === "Job" && resource.metadata?.name === name,
      );
      assert.ok(job?.metadata && job.spec);
      // This verifies readback, not installation. Delegate reconciliation away
      // from the Job controller; no Pod runs and we supply Complete deliberately.
      job.metadata.namespace = namespace;
      job.spec.managedBy = "example.invalid/handoff-readback";
      await applyManifest(JSON.stringify(job));
      const now = new Date().toISOString();
      const status = {
        conditions: [
          { type: "SuccessCriteriaMet", status: "True", lastTransitionTime: now },
          { type: "Complete", status: "True", lastTransitionTime: now },
        ],
        succeeded: 1,
        startTime: now,
        completionTime: now,
      };
      return (
        await admin(
          "patch",
          "job",
          name,
          "--subresource=status",
          "--type=merge",
          "-p",
          JSON.stringify({ status }),
          "-o",
          "jsonpath={.metadata.uid}",
        )
      ).trim();
    }

    const first = await retainedJob(false);
    assert.ok(first);
    handoff("doctor", 0, /install hook\): complete/, "--expect-job-uid", first);
    await admin("delete", "job", name);
    const second = await retainedJob(true);
    assert.ok(second);
    assert.notEqual(second, first);
    handoff("plan", 1, /1\. Recover the original installation record/, "--expect-job-uid", first);
    handoff("doctor", 0, /upgrade hook\): complete/, "--expect-job-uid", second);
  },
);
