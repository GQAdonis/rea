import { createHash } from "node:crypto";
import { constants, type BigIntStats } from "node:fs";
import { lstat, open } from "node:fs/promises";
import type { BinaryTarget } from "../domain/binaryTarget.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisAccessDeniedError,
  AnalysisArtifactChangedError,
  AnalysisResourceConstraintError,
} from "../domain/analysisErrorCore.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { err, ok, type Result } from "../domain/result.js";
import { NATIVE_MACOS_PROVIDER_IDENTITY } from "./NativeMacOSProviderMetadata.js";

/** Binding of commands to the selected executable's registered content/version. */
export interface SignatureTargetBinding {
  readonly identity: string;
}

const identity = (stat: BigIntStats): string =>
  [stat.dev, stat.ino, stat.size, stat.mtimeNs, stat.ctimeNs].join(":");

const changedTarget = (target: BinaryTarget, reason: string) =>
  err(
    new AnalysisArtifactChangedError("inspect_signature", target.path, reason),
  );

const signatureReadFailure = (
  target: BinaryTarget,
  cause: unknown,
): AnalysisError => {
  const code =
    cause instanceof Error && "code" in cause ? cause.code : undefined;
  if (code === "EACCES" || code === "EPERM")
    return new AnalysisAccessDeniedError(
      "inspect_signature",
      target.path,
      code,
      { cause },
    );
  if (code === "ENOENT" || code === "ENOTDIR" || code === "ELOOP")
    return new AnalysisArtifactChangedError(
      "inspect_signature",
      target.path,
      `Registered signature target is no longer readable (${code}): ${target.path}`,
      { cause },
    );
  return new ProviderAdapterError(
    NATIVE_MACOS_PROVIDER_IDENTITY.id,
    "inspect_signature",
    {
      cause,
      diagnostics: {
        path: target.path,
        phase: "target-version-binding",
        system_code: typeof code === "string" ? code : null,
        reason: cause instanceof Error ? cause.message : String(cause),
      },
    },
  );
};

/** Establish a bounded-memory digest/version baseline before external commands run. */
export const bindSignatureTarget = async (
  target: BinaryTarget,
  signal?: AbortSignal,
): Promise<Result<SignatureTargetBinding, AnalysisError>> => {
  signal?.throwIfAborted();
  try {
    const before = await lstat(target.path, { bigint: true });
    if (!before.isFile() || before.isSymbolicLink())
      return changedTarget(
        target,
        `Signature target is no longer a regular file: ${target.path}`,
      );
    const file = await open(
      target.path,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    );
    try {
      const opened = await file.stat({ bigint: true });
      if (identity(opened) !== identity(before))
        return changedTarget(
          target,
          `Signature target changed before open: ${target.path}`,
        );
      const size = Number(opened.size);
      if (!Number.isSafeInteger(size))
        return err(
          new AnalysisResourceConstraintError(
            "inspect_signature",
            "file-size",
            `Signature target size is not exactly representable: ${target.path}`,
            null,
          ),
        );
      const hash = createHash("sha256");
      const chunk = Buffer.alloc(64 * 1024);
      let position = 0;
      while (position < size) {
        signal?.throwIfAborted();
        const { bytesRead } = await file.read(
          chunk,
          0,
          Math.min(chunk.length, size - position),
          position,
        );
        if (bytesRead === 0)
          return changedTarget(
            target,
            `Signature target was truncated while hashing: ${target.path}`,
          );
        hash.update(chunk.subarray(0, bytesRead));
        position += bytesRead;
      }
      const observed = hash.digest("hex");
      if (observed !== target.sha256)
        return changedTarget(
          target,
          `Signature target digest changed: ${target.path}; expected ${target.sha256}, observed ${observed}`,
        );
      const after = await file.stat({ bigint: true });
      const current = await lstat(target.path, { bigint: true });
      if (
        identity(after) !== identity(opened) ||
        identity(current) !== identity(opened)
      )
        return changedTarget(
          target,
          `Signature target changed while establishing its version: ${target.path}`,
        );
      return ok({ identity: identity(opened) });
    } finally {
      await file.close();
    }
  } catch (cause: unknown) {
    signal?.throwIfAborted();
    return err(signatureReadFailure(target, cause));
  }
};

/** Reject target drift across signature command captures. */
export const verifySignatureTarget = async (
  target: BinaryTarget,
  binding: SignatureTargetBinding,
  signal?: AbortSignal,
): Promise<Result<void, AnalysisError>> => {
  signal?.throwIfAborted();
  try {
    const current = await lstat(target.path, { bigint: true });
    return current.isFile() && identity(current) === binding.identity
      ? ok(undefined)
      : changedTarget(
          target,
          `Signature target changed during inspection: ${target.path}`,
        );
  } catch (cause: unknown) {
    signal?.throwIfAborted();
    return err(signatureReadFailure(target, cause));
  }
};
