import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import tls from "node:tls";
import net from "node:net";

export class CaManager {
  private caCertPath: string;
  private caKeyPath: string;
  private certsDir: string;
  private secureContextCache = new Map<string, tls.SecureContext>();

  constructor(private readonly directory: string = path.resolve("data")) {
    this.caCertPath = path.join(this.directory, "ca.crt");
    this.caKeyPath = path.join(this.directory, "ca.key");
    this.certsDir = path.join(this.directory, "certs");
    this.ensureCa();
  }

  ensureCa(): void {
    if (!fs.existsSync(this.directory)) {
      fs.mkdirSync(this.directory, { recursive: true });
    }
    if (!fs.existsSync(this.certsDir)) {
      fs.mkdirSync(this.certsDir, { recursive: true });
    }
    if (!fs.existsSync(this.caCertPath) || !fs.existsSync(this.caKeyPath)) {
      execFileSync("openssl", [
        "req", "-x509", "-new", "-nodes",
        "-keyout", this.caKeyPath,
        "-out", this.caCertPath,
        "-days", "3650",
        "-subj", "/CN=Local HTTP Lab Root CA/O=Local HTTP Lab/OU=Security Testing"
      ], { stdio: "pipe" });
    }
  }

  getCaCertPem(): string {
    this.ensureCa();
    return fs.readFileSync(this.caCertPath, "utf8");
  }

  getSecureContext(host: string): tls.SecureContext {
    const cleanHost = host.toLowerCase().replace(/^\[|\]$/g, "").replace(/:\d+$/, "");
    if (this.secureContextCache.has(cleanHost)) {
      return this.secureContextCache.get(cleanHost)!;
    }

    this.ensureCa();
    const safeFilename = cleanHost.replace(/[^a-z0-9.-]/g, "_");
    const hostKeyPath = path.join(this.certsDir, `${safeFilename}.key`);
    const hostCertPath = path.join(this.certsDir, `${safeFilename}.crt`);

    if (!fs.existsSync(hostKeyPath) || !fs.existsSync(hostCertPath)) {
      const extCnfPath = path.join(this.certsDir, `${safeFilename}.cnf`);
      const csrPath = path.join(this.certsDir, `${safeFilename}.csr`);
      const isIp = net.isIP(cleanHost) > 0;
      const san = isIp ? `IP:${cleanHost}` : `DNS:${cleanHost},DNS:*.${cleanHost}`;

      fs.writeFileSync(extCnfPath, `[req]\ndistinguished_name=req\n[san]\nsubjectAltName=${san}\n`, "utf8");

      execFileSync("openssl", [
        "req", "-new", "-nodes",
        "-keyout", hostKeyPath,
        "-out", csrPath,
        "-subj", `/CN=${cleanHost}`
      ], { stdio: "pipe" });

      execFileSync("openssl", [
        "x509", "-req", "-in", csrPath,
        "-CA", this.caCertPath,
        "-CAkey", this.caKeyPath,
        "-CAcreateserial",
        "-out", hostCertPath,
        "-days", "365",
        "-extfile", extCnfPath,
        "-extensions", "san"
      ], { stdio: "pipe" });

      try { fs.unlinkSync(csrPath); } catch {}
      try { fs.unlinkSync(extCnfPath); } catch {}
    }

    const key = fs.readFileSync(hostKeyPath, "utf8");
    const cert = fs.readFileSync(hostCertPath, "utf8");
    const context = tls.createSecureContext({ key, cert });
    this.secureContextCache.set(cleanHost, context);
    return context;
  }
}
