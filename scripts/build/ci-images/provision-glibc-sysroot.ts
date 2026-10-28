#!/usr/bin/env bun

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { lstat, mkdir, mkdtemp, readdir, readFile, readlink, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { downloadWithRetry } from "../download.ts";
import { locations, pins } from "./spec.ts";

type Arch = "x64" | "aarch64";

const arch = process.argv[2];
if (arch !== "x64" && arch !== "aarch64") {
  throw new Error("usage: provision-glibc-sysroot.ts <x64|aarch64>");
}
if (process.getuid?.() !== 0) {
  throw new Error("provisioning /opt/linux-sysroot-glibc* requires root");
}

const root = locations.glibcSysroot[arch];
const cxxHeaders = join(root, "usr", "include", "c++", "13");
if (existsSync(cxxHeaders)) {
  console.log(`glibc ${arch} sysroot already exists at ${root}`);
  process.exit(0);
}

const debianArch = arch === "x64" ? "amd64" : "arm64";
const cpuArch = arch === "x64" ? "x86_64" : "aarch64";
const triple = `${cpuArch}-linux-gnu`;
const ubuntu = pins.glibcSysroot.ubuntu;
const mirror =
  arch === "x64" ? "http://archive.ubuntu.com/ubuntu" : "http://ports.ubuntu.com/ubuntu-ports";
const scratch = await mkdtemp(join(tmpdir(), "bun-glibc-sysroot-"));

function run(command: string, args: string[], options: { capture?: boolean; tolerateFailure?: boolean } = {}): string {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    stdio: options.capture ? ["ignore", "pipe", "inherit"] : "inherit",
  });
  if (result.error) throw result.error;
  if (result.status !== 0 && !options.tolerateFailure) {
    throw new Error(`${command} exited with status ${result.status}`);
  }
  return result.stdout ?? "";
}

async function verify(path: string, expected: string): Promise<void> {
  const actual = createHash("sha256").update(await readFile(path)).digest("hex");
  if (actual !== expected.toLowerCase()) {
    throw new Error(`${path} has sha256 ${actual}, expected ${expected}`);
  }
}

async function fixAbsoluteSymlinks(directory: string): Promise<void> {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    const stat = await lstat(path);
    if (stat.isSymbolicLink()) {
      const target = await readlink(path);
      if (target.startsWith("/")) {
        await rm(path);
        await symlink(`${root}${target}`, path);
      }
    } else if (stat.isDirectory()) {
      await fixAbsoluteSymlinks(path);
    }
  }
}

try {
  run("apt-get", ["update", "-qq"]);
  run("apt-get", ["install", "-y", "-qq", "--no-install-recommends", "skopeo"]);

  const image = join(scratch, `image-${debianArch}`);
  run("skopeo", [
    "copy",
    "--override-arch",
    debianArch,
    `docker://docker.io/library/ubuntu@${ubuntu.image}`,
    `dir:${image}`,
  ]);

  await rm(root, { recursive: true, force: true });
  await mkdir(root, { recursive: true });
  const manifest = JSON.parse(await readFile(join(image, "manifest.json"), "utf8")) as {
    layers: { digest: string }[];
  };
  for (const layer of manifest.layers) {
    const digest = layer.digest.replace(/^sha256:/, "");
    run("tar", ["-xzf", join(image, digest), "-C", root], { tolerateFailure: true });
  }

  for (const [index, deb] of pins.glibcSysroot.debs.entries()) {
    const file = join(scratch, `libc-${index}.deb`);
    const url = `${mirror}/pool/main/${deb.directory}/${deb.name}_${deb.version}_${debianArch}.deb`;
    await downloadWithRetry(url, file, `glibc ${arch} sysroot`);
    await verify(file, deb.sha256[arch]);
    run("dpkg-deb", ["-x", file, root]);
  }

  await fixAbsoluteSymlinks(root);
  if (!existsSync(join(root, "lib", triple, "libc.so.6"))) {
    await mkdir(join(root, "lib"), { recursive: true });
    await symlink(`../usr/lib/${triple}`, join(root, "lib", triple));
  }
  if (arch === "x64" && !existsSync(join(root, "lib64"))) {
    await symlink(`usr/lib/${triple}`, join(root, "lib64"));
  }

  const gccSources = pins.glibcSysroot.gccDebs;
  const gccArchive = join(scratch, "gcc.deb.tar.gz");
  await downloadWithRetry(
    `${gccSources.url}/gcc-13-focal-${debianArch}.tar.gz`,
    gccArchive,
    `glibc ${arch} sysroot`,
  );
  await verify(gccArchive, gccSources.sha256[arch]);

  const gccDir = join(scratch, "gcc");
  await mkdir(gccDir);
  run("tar", ["-xzf", gccArchive, "-C", gccDir]);
  for await (const deb of new Bun.Glob("**/*.deb").scan({ cwd: gccDir, absolute: true })) {
    run("dpkg-deb", ["-x", deb, root]);
  }

  if (!existsSync(cxxHeaders)) {
    throw new Error(`glibc ${arch} sysroot is incomplete: ${cxxHeaders} was not installed`);
  }
  console.log(`provisioned glibc ${arch} sysroot at ${root} from Ubuntu ${ubuntu.release}`);
} finally {
  await rm(scratch, { recursive: true, force: true });
}
