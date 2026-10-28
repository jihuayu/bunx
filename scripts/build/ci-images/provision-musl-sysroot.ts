#!/usr/bin/env bun

import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { chmod, mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { downloadWithRetry } from "../download.ts";
import { locations, pins } from "./spec.ts";

type Arch = "x64" | "aarch64";

const arch = process.argv[2];
if (arch !== "x64" && arch !== "aarch64") {
  throw new Error("usage: provision-musl-sysroot.ts <x64|aarch64>");
}
if (process.getuid?.() !== 0) {
  throw new Error("provisioning /opt/linux-sysroot-musl* requires root");
}

const root = locations.muslSysroot[arch];
const libc = join(root, "usr", "lib", "libc.so");
if (existsSync(libc)) {
  console.log(`musl ${arch} sysroot already exists at ${root}`);
  process.exit(0);
}

const hostArch = process.arch === "arm64" ? "aarch64" : "x86_64";
const targetArch = arch === "x64" ? "x86_64" : "aarch64";
const release = pins.muslSysroot.alpineRelease;
const repository = `https://dl-cdn.alpinelinux.org/alpine/v${release}/main`;
const scratch = await mkdtemp(join(tmpdir(), "bun-musl-sysroot-"));

function run(command: string, args: string[], capture = false): string {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    stdio: capture ? ["ignore", "pipe", "inherit"] : "inherit",
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`${command} exited with status ${result.status}`);
  }
  return result.stdout ?? "";
}

try {
  const index = join(scratch, "APKINDEX.tar.gz");
  await downloadWithRetry(`${repository}/${hostArch}/APKINDEX.tar.gz`, index, "musl sysroot");

  const packages = run("tar", ["-xzOf", index, "APKINDEX"], true).split(/\n\n/);
  const apkTools = packages.find(entry => entry.split("\n").includes("P:apk-tools-static"));
  const version = apkTools?.match(/^V:(.+)$/m)?.[1];
  if (!version) throw new Error("Alpine's APKINDEX has no apk-tools-static package");

  const archive = join(scratch, "apk-tools-static.apk");
  await downloadWithRetry(
    `${repository}/${hostArch}/apk-tools-static-${version}.apk`,
    archive,
    "musl sysroot",
  );

  const apkDir = join(scratch, "apk");
  await mkdir(apkDir);
  run("tar", ["-xzf", archive, "-C", apkDir, "sbin/apk.static"]);
  const apk = join(apkDir, "sbin", "apk.static");
  await chmod(apk, 0o755);

  await rm(root, { recursive: true, force: true });
  await mkdir(root, { recursive: true });
  run(apk, [
    "--arch",
    targetArch,
    "--root",
    root,
    "--repository",
    repository,
    "--allow-untrusted",
    "--no-cache",
    "--initdb",
    "add",
    "musl-dev",
    "libc-dev",
    "linux-headers",
    "g++",
    "libstdc++-dev",
  ]);

  await rm(join(root, "var", "log", "apk.log"), { force: true });
  if (!existsSync(libc)) {
    throw new Error(`musl ${arch} sysroot is incomplete: ${libc} was not installed`);
  }
  console.log(`provisioned musl ${arch} sysroot at ${root} from Alpine ${release}`);
} finally {
  await rm(scratch, { recursive: true, force: true });
}
