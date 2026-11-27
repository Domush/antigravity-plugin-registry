import crypto from "node:crypto";
import fs from "node:fs/promises";
import { createWriteStream } from "node:fs";
import path from "node:path";
import { Readable, Transform } from "node:stream";
import { pipeline } from "node:stream/promises";
import zlib from "node:zlib";
import tar from "tar-stream";

/**
 * Strip the GitHub archive top-level directory prefix (`owner-repo-sha/`).
 */
export function stripTopLevelDir(rawName) {
  const normalized = rawName.replaceAll("\\", "/").replace(/^\.\/+/, "");
  if (!normalized || normalized === "pax_global_header") return null;
  const slashIdx = normalized.indexOf("/");
  if (slashIdx === -1) return null; // Root directory entry itself
  const stripped = normalized.slice(slashIdx + 1);
  return stripped.length > 0 ? stripped : null;
}

/**
 * Resolve a relative archive path strictly inside `sandboxDir`, rejecting zip-slip traversal.
 */
export function resolveInsideSandbox(sandboxDir, relPath) {
  const segments = relPath.split("/");
  if (relPath.startsWith("/") || segments.some((s) => s === "..")) {
    throw new Error(`Zip-slip path traversal detected: ${relPath}`);
  }
  const resolvedRoot = path.resolve(sandboxDir);
  const dest = path.resolve(resolvedRoot, relPath);
  const rootPrefix = resolvedRoot.endsWith(path.sep) ? resolvedRoot : `${resolvedRoot}${path.sep}`;
  if (dest !== resolvedRoot && !dest.startsWith(rootPrefix)) {
    throw new Error(`Path escapes sandbox: ${relPath}`);
  }
  return dest;
}

/**
 * Stream, verify size/entry limits, and safely extract a repository tarball into `sandboxDir`.
 */
export async function downloadAndExtractTarball(
  tarballUrl,
  sandboxDir,
  { githubFetchFn, maxArchiveBytes, maxUncompressedBytes, maxFiles }
) {
  if (!tarballUrl || !sandboxDir || typeof githubFetchFn !== "function") {
    throw new Error("downloadAndExtractTarball requires tarballUrl, sandboxDir, and githubFetchFn.");
  }

  const res = await githubFetchFn(tarballUrl, { accept: "application/vnd.github+json" });
  if (!res.ok || !res.body) {
    throw new Error(`Failed to fetch tarball (${res.status}): ${tarballUrl}`);
  }

  let archiveBytes = 0;
  let uncompressedBytes = 0;
  let fileCount = 0;

  const byteLimiter = new Transform({
    transform(chunk, _encoding, callback) {
      archiveBytes += chunk.length;
      if (archiveBytes > maxArchiveBytes) {
        callback(new Error(`Archive exceeds ${maxArchiveBytes} byte limit`));
        return;
      }
      callback(null, chunk);
    },
  });

  const extract = tar.extract();

  extract.on("entry", (header, stream, next) => {
    const handleEntry = async () => {
      if (header.type === "symlink" || header.type === "link") {
        stream.resume();
        throw new Error(`Rejected archive containing ${header.type}: ${header.name}`);
      }

      const relPath = stripTopLevelDir(header.name);
      if (!relPath) {
        stream.resume();
        return;
      }

      const destPath = resolveInsideSandbox(sandboxDir, relPath);

      if (header.type === "directory") {
        await fs.mkdir(destPath, { recursive: true });
        stream.resume();
        return;
      }

      if (header.type !== "file") {
        stream.resume();
        return;
      }

      fileCount += 1;
      if (fileCount > maxFiles) {
        stream.resume();
        throw new Error(`Archive exceeds max file count (${maxFiles})`);
      }

      await fs.mkdir(path.dirname(destPath), { recursive: true });
      const fileLimiter = new Transform({
        transform(chunk, _encoding, callback) {
          uncompressedBytes += chunk.length;
          if (uncompressedBytes > maxUncompressedBytes) {
            callback(new Error(`Uncompressed content exceeds ${maxUncompressedBytes} byte limit`));
            return;
          }
          callback(null, chunk);
        },
      });

      await pipeline(stream, fileLimiter, createWriteStream(destPath, { flags: "wx" }));
    };

    handleEntry()
      .then(() => next())
      .catch((err) => {
        stream.destroy(err);
        next(err);
      });
  });

  await pipeline(Readable.fromWeb(res.body), byteLimiter, zlib.createGunzip(), extract);
  return { archiveBytes, uncompressedBytes, fileCount };
}

async function collectRelativeFiles(rootDir, currentDir = rootDir, results = []) {
  const entries = await fs.readdir(currentDir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(currentDir, entry.name);
    if (entry.isDirectory()) {
      await collectRelativeFiles(rootDir, fullPath, results);
    } else if (entry.isFile()) {
      const relPosix = path.relative(rootDir, fullPath).split(path.sep).join("/");
      results.push(relPosix);
    }
  }
  return results;
}

/**
 * Deterministic tree hash shared by crawler and local client installer:
 * 1. Sort all relative POSIX file paths by UTF-16 code unit order (locale-independent).
 * 2. For each file, feed: `<relPosixPath>\0<byteLength>\0<rawFileBytes>\0` into SHA-256.
 */
export async function computeContentTreeSha256(rootDir) {
  const files = await collectRelativeFiles(rootDir);
  files.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));

  const hash = crypto.createHash("sha256");
  const nul = Buffer.from([0]);

  for (const relPath of files) {
    const fileBytes = await fs.readFile(path.join(rootDir, ...relPath.split("/")));
    hash.update(relPath, "utf8");
    hash.update(nul);
    hash.update(String(fileBytes.length), "utf8");
    hash.update(nul);
    hash.update(fileBytes);
    hash.update(nul);
  }

  return { contentTreeSha256: hash.digest("hex"), files };
}
