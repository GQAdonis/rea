import { chmod, mkdir, rename, rm, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { NativeMacOSProvider } from "../../../../src/native/NativeMacOSProvider.js";
import {
  bindSignatureTarget,
  verifySignatureTarget,
} from "../../../../src/native/SignatureTargetBinding.js";
import {
  NativeCommandFailure,
  type NativeCommandRunner,
} from "../../../../src/native/CommandRunner.js";
import { err } from "../../../../src/domain/result.js";
import { projectAnalysisError } from "../../../../src/domain/analysisErrorProjection.js";
import {
  NativeFixtureRunner,
  nativeMachoTargetForFile,
} from "../../../fixtures/nativeCommands.js";
import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";

const CONTENT = "registered executable bytes";
const fixture = async () => {
  const directory = await createTestTempDirectory("rea-signature-binding-");
  const path = join(directory, "program");
  await writeFile(path, CONTENT);
  return {
    directory,
    path,
    target: await nativeMachoTargetForFile(path),
  };
};

class Captures extends NativeFixtureRunner {
  calls = 0;
  constructor(
    private readonly onCapture?: (args: readonly string[]) => Promise<void>,
  ) {
    super();
  }
  override async run(tool: string, args: readonly string[]) {
    this.calls += 1;
    await this.onCapture?.(args);
    return super.run(tool, args);
  }
}

describe("native signature target identity", () => {
  it("inspects an unchanged registered executable", async () => {
    const { target } = await fixture();
    const result = await new NativeMacOSProvider(new Captures(), "darwin")
      .createClient(target)
      .execute("inspect_signature", {});
    expect(result.ok && result.value.result).toMatchObject({
      signed: true,
      identifier: "com.example.fixture",
    });
  });

  it.each(["changed", "missing", "directory", "symlink"] as const)(
    "rejects a %s target before commands run",
    async (replacement) => {
      const { path, target } = await fixture();
      if (replacement === "changed") await writeFile(path, "replacement bytes");
      else {
        await rm(path);
        if (replacement === "directory") await mkdir(path);
        if (replacement === "symlink") {
          await symlink(join(path, "missing"), path);
        }
      }
      const runner = new Captures();
      const result = await new NativeMacOSProvider(runner, "darwin")
        .createClient(target)
        .execute("inspect_signature", {});
      expect(result.ok).toBe(false);
      if (result.ok) throw new Error("Expected target-change failure");
      expect(projectAnalysisError(result.error)).toMatchObject({
        code: "artifact_changed",
        details: { path },
      });
      expect(runner.calls).toBe(0);
    },
  );

  it.each(["replace", "remove", "rewrite"] as const)(
    "rejects %s after capturing signature metadata",
    async (change) => {
      const { path, target } = await fixture();
      const runner = new Captures(async (args) => {
        if (!args.includes("--entitlements")) return;
        if (change === "remove") await rm(path);
        else if (change === "rewrite") await writeFile(path, CONTENT);
        else {
          const replacement = `${path}.replacement`;
          await writeFile(replacement, CONTENT);
          await rename(replacement, path);
        }
      });
      const result = await new NativeMacOSProvider(runner, "darwin")
        .createClient(target)
        .execute("inspect_signature", {});
      expect(result.ok).toBe(false);
      if (result.ok) throw new Error("Expected target-change failure");
      expect(projectAnalysisError(result.error)).toMatchObject({
        code: "artifact_changed",
        details: { path },
      });
    },
  );

  it.skipIf(process.getuid?.() === 0)(
    "preserves read permission denial before commands",
    async () => {
      const { path, target } = await fixture();
      await chmod(path, 0);
      const runner = new Captures();
      try {
        const result = await new NativeMacOSProvider(runner, "darwin")
          .createClient(target)
          .execute("inspect_signature", {});
        expect(result.ok).toBe(false);
        if (result.ok) throw new Error("Expected access denial");
        expect(projectAnalysisError(result.error)).toMatchObject({
          code: "access_denied",
          details: { path },
        });
        expect(runner.calls).toBe(0);
      } finally {
        await chmod(path, 0o600);
      }
    },
  );

  it.skipIf(process.getuid?.() === 0)(
    "preserves permission denial during final version lookup",
    async () => {
      const { directory, path, target } = await fixture();
      const runner = new Captures(async (args) => {
        if (args.includes("--entitlements")) await chmod(directory, 0);
      });
      try {
        const result = await new NativeMacOSProvider(runner, "darwin")
          .createClient(target)
          .execute("inspect_signature", {});
        expect(result.ok).toBe(false);
        if (result.ok) throw new Error("Expected access denial");
        expect(projectAnalysisError(result.error)).toMatchObject({
          code: "access_denied",
          details: { path },
        });
      } finally {
        await chmod(directory, 0o700);
      }
    },
  );
});

it.each([
  ["display", "result"],
  ["requirements", "result"],
  ["entitlements", "result"],
  ["slice", "result"],
  ["display", "throw"],
  ["requirements", "diagnostic"],
] as const)(
  "reports a removed target before the %s capture's %s failure can hide it",
  async (stage, failure) => {
    const { path, target } = await fixture();
    const replay = new NativeFixtureRunner();
    const unsigned = new NativeFixtureRunner(
      { codesign: "code object is not signed at all\n" },
      1,
    );
    let failed = false;
    const runner: NativeCommandRunner = {
      async run(tool, args) {
        const slice = args.includes("-a");
        const selected =
          stage === "slice"
            ? slice
            : stage === "requirements"
              ? args.includes("-r-")
              : stage === "entitlements"
                ? args.includes("--entitlements")
                : !args.includes("-r-") &&
                  !args.includes("--entitlements") &&
                  !slice;
        if (selected) {
          failed = true;
          await rm(path);
          if (failure === "throw")
            throw new Error("codesign target disappeared");
          if (failure === "diagnostic")
            return new NativeFixtureRunner(
              { codesign: "invalid or unsupported format\n" },
              1,
            ).run(tool, args);
          return err(new NativeCommandFailure(tool, "nonzero-exit", 1));
        }
        if (stage === "slice" && args.includes("-r-"))
          return unsigned.run(tool, args);
        return replay.run(tool, args);
      },
    };
    const result = await new NativeMacOSProvider(runner, "darwin")
      .createClient(target)
      .execute("inspect_signature", {});
    expect(failed).toBe(true);
    expect(result).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisArtifactChangedError" },
    });
  },
);

it("rejects an intermediate replacement before a later capture can restore the original inode", async () => {
  const { path, target } = await fixture();
  const original = `${path}.original`;
  const runner = new Captures(async (args) => {
    if (args.includes("-r-")) {
      await rename(path, original);
      await writeFile(path, "different executable");
    } else if (args.includes("--entitlements")) {
      await rm(path);
      await rename(original, path);
    }
  });
  const result = await new NativeMacOSProvider(runner, "darwin")
    .createClient(target)
    .execute("inspect_signature", {});
  expect(result).toMatchObject({
    ok: false,
    error: { _tag: "AnalysisArtifactChangedError" },
  });
});

it("returns typed cancellation during target acquisition before commands run", async () => {
  const { path } = await fixture();
  await writeFile(path, Buffer.alloc(4 * 1024 * 1024, 42));
  const target = await nativeMachoTargetForFile(path);
  const controller = new AbortController();
  const runner = new Captures();
  const pending = new NativeMacOSProvider(runner, "darwin")
    .createClient(target)
    .execute("inspect_signature", {}, { signal: controller.signal });
  controller.abort();
  const result = await pending;
  expect(result).toMatchObject({
    ok: false,
    error: { _tag: "AnalysisCancelledError" },
  });
  expect(!result.ok && projectAnalysisError(result.error).code).toBe(
    "cancelled",
  );
  expect(runner.calls).toBe(0);
});

it("returns typed cancellation at binding entry and final verification", async () => {
  const { target } = await fixture();
  const binding = await bindSignatureTarget(target);
  if (!binding.ok) throw binding.error;
  const signal = AbortSignal.abort();
  await expect(bindSignatureTarget(target, signal)).resolves.toMatchObject({
    ok: false,
    error: { _tag: "AnalysisCancelledError" },
  });
  await expect(
    verifySignatureTarget(target, binding.value, signal),
  ).resolves.toMatchObject({
    ok: false,
    error: { _tag: "AnalysisCancelledError" },
  });
});

it("preserves cancellation after a capture instead of classifying it as invalid output", async () => {
  const { target } = await fixture();
  const controller = new AbortController();
  const runner = new Captures(async () => {
    controller.abort();
  });
  const result = await new NativeMacOSProvider(runner, "darwin")
    .createClient(target)
    .execute("inspect_signature", {}, { signal: controller.signal });
  expect(result).toMatchObject({
    ok: false,
    error: { _tag: "AnalysisCancelledError" },
  });
});
