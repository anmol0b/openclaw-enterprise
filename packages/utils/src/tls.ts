import { X509Certificate } from "node:crypto";

/** Accept public CA certificates only, before projecting trust into a workload. */
export function publicCaBundle(value: string): string {
  const pem = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
  const certificates = typeof value === "string" ? value.match(pem) : null;
  if (!certificates?.length || value.replace(pem, "").trim() !== "") {
    throw new Error("TLS trust must contain only PEM CA certificates.");
  }
  const publicCertificates: string[] = [];
  for (const certificate of certificates) {
    let parsed: X509Certificate;
    try {
      parsed = new X509Certificate(certificate);
    } catch {
      throw new Error("TLS trust contains an invalid certificate.");
    }
    if (!parsed.ca) {
      throw new Error("TLS trust contains a non-CA certificate.");
    }
    publicCertificates.push(parsed.toString().trim());
  }
  return publicCertificates.join("\n") + "\n";
}
