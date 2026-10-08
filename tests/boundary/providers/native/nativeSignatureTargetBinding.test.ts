import { createHash } from "node:crypto";
import { chmod, mkdir, rename, rm, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { NativeMacOSProvider } from "../../../../src/native/NativeMacOSProvider.js";
import { projectAnalysisError } from "../../../../src/domain/analysisErrorProjection.js";
import {
  NativeFixtureRunner,
  nativeMachoTarget,
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
    target: {
      ...nativeMachoTarget(path),
      sha256: createHash("sha256").update(CONTENT).digest("hex"),
    },
  };
};

class Captures extends NativeFixtureRunner {
  calls = 0;
  constructor(private readonly onCapture?: (count: number) => Promise<void>) {
    super();
  }
  override async run(tool: string, args: readonly string[]) {
    this.calls += 1;
    await this.onCapture?.(this.calls);
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
      const runner = new Captures(async (count) => {
        if (count !== 3) return;
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
      const runner = new Captures(async (count) => {
        if (count === 3) await chmod(directory, 0);
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
