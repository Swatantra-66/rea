import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { createTestTempDirectory } from "../../tests/fixtures/temporaryDirectory.js";
import {
  elfFuseImage,
  OBSIDIAN_FUSE_BYTES,
  peFuseImage,
  structuredElfFuseImage,
  structuredPeFuseImage,
} from "../../tests/fixtures/electron/fuseImage.js";
import { ElectronFuseProvider } from "./ElectronFuseProvider.js";
import { ElectronFuseService } from "../application/electron/ElectronFuseService.js";
import { parseEvidence } from "../domain/evidence.js";

const provider = new ElectronFuseProvider();
const service = new ElectronFuseService(provider);

describe("Electron fuse container architecture detection", () => {
  it("detects ELF architectures (x86_64, arm64, x86, arm) from fixed headers", async () => {
    const root = await createTestTempDirectory("rea-electron-fuses-elf-arch-");
    const targets = [
      { name: "elf-x64", machine: 62, expected: "x86_64", class_: 2 },
      { name: "elf-arm64", machine: 183, expected: "arm64", class_: 2 },
      { name: "elf-x86", machine: 3, expected: "x86", class_: 1 },
      { name: "elf-arm", machine: 40, expected: "arm", class_: 1 },
    ] as const;

    for (const { name, machine, class_ } of targets) {
      const image = structuredElfFuseImage(
        machine,
        OBSIDIAN_FUSE_BYTES,
        class_,
      );
      const targetPath = join(root, name);
      await writeFile(targetPath, image.bytes);

      const inspectResult = await provider.inspect({ path: targetPath });
      expect(inspectResult.ok).toBe(true);
      if (inspectResult.ok) {
        expect(inspectResult.value.artifact.format).toBe("elf");
        expect(inspectResult.value.slices[0]?.architecture).toBe(
          targets.find((t) => t.name === name)!.expected,
        );
        expect(
          inspectResult.value.slices[0]?.sentinels[0]?.sentinel_offset,
        ).toBe(image.sentinelOffset);
      }

      const serviceResult = await service.inspect({ path: targetPath });
      expect(serviceResult.ok).toBe(true);
      if (serviceResult.ok) {
        const evidence = parseEvidence(serviceResult.value);
        expect(evidence.subject?.architecture).toBe(
          targets.find((t) => t.name === name)!.expected,
        );
      }
    }
  });

  it("detects PE architectures (x86_64, arm64, x86) from COFF headers", async () => {
    const root = await createTestTempDirectory("rea-electron-fuses-pe-arch-");
    const targets = [
      { name: "pe-x64.exe", machine: 0x8664, expected: "x86_64" },
      { name: "pe-arm64.exe", machine: 0xaa64, expected: "arm64" },
      { name: "pe-x86.exe", machine: 0x014c, expected: "x86" },
    ] as const;

    for (const { name, machine, expected } of targets) {
      const image = structuredPeFuseImage(machine, OBSIDIAN_FUSE_BYTES);
      const targetPath = join(root, name);
      await writeFile(targetPath, image.bytes);

      const inspectResult = await provider.inspect({ path: targetPath });
      expect(inspectResult.ok).toBe(true);
      if (inspectResult.ok) {
        expect(inspectResult.value.artifact.format).toBe("pe");
        expect(inspectResult.value.slices[0]?.architecture).toBe(expected);
        expect(
          inspectResult.value.slices[0]?.sentinels[0]?.sentinel_offset,
        ).toBe(image.sentinelOffset);
      }

      const serviceResult = await service.inspect({ path: targetPath });
      expect(serviceResult.ok).toBe(true);
      if (serviceResult.ok) {
        const evidence = parseEvidence(serviceResult.value);
        expect(evidence.subject?.architecture).toBe(expected);
      }
    }
  });

  it("leaves unrecognized machine types as null architecture without failing fuse reads", async () => {
    const root = await createTestTempDirectory("rea-electron-fuses-unknown-");
    const elfUnknown = structuredElfFuseImage(0x9999, OBSIDIAN_FUSE_BYTES);
    const peUnknown = structuredPeFuseImage(0x9999, OBSIDIAN_FUSE_BYTES);

    const elfPath = join(root, "unknown.elf");
    const pePath = join(root, "unknown.exe");
    await writeFile(elfPath, elfUnknown.bytes);
    await writeFile(pePath, peUnknown.bytes);

    const elfResult = await provider.inspect({ path: elfPath });
    expect(elfResult.ok).toBe(true);
    if (elfResult.ok) {
      expect(elfResult.value.artifact.format).toBe("elf");
      expect(elfResult.value.slices[0]?.architecture).toBeNull();
      expect(elfResult.value.slices[0]?.sentinel_count).toBe(1);
    }

    const peResult = await provider.inspect({ path: pePath });
    expect(peResult.ok).toBe(true);
    if (peResult.ok) {
      expect(peResult.value.artifact.format).toBe("pe");
      expect(peResult.value.slices[0]?.architecture).toBeNull();
      expect(peResult.value.slices[0]?.sentinel_count).toBe(1);
    }

    const serviceResult = await service.inspect({ path: elfPath });
    expect(serviceResult.ok).toBe(true);
    if (serviceResult.ok) {
      const evidence = parseEvidence(serviceResult.value);
      expect(evidence.subject?.architecture).toBeNull();
    }
  });

  it("leaves minimal/synthetic headers as null architecture without failing", async () => {
    const root = await createTestTempDirectory("rea-electron-fuses-minimal-");
    const elfMinimal = elfFuseImage(OBSIDIAN_FUSE_BYTES);
    const peMinimal = peFuseImage(OBSIDIAN_FUSE_BYTES);

    const elfPath = join(root, "min.elf");
    const pePath = join(root, "min.exe");
    await writeFile(elfPath, elfMinimal.bytes);
    await writeFile(pePath, peMinimal.bytes);

    const elfResult = await provider.inspect({ path: elfPath });
    expect(elfResult.ok).toBe(true);
    if (elfResult.ok) {
      expect(elfResult.value.artifact.format).toBe("elf");
      expect(elfResult.value.slices[0]?.architecture).toBeNull();
    }

    const peResult = await provider.inspect({ path: pePath });
    expect(peResult.ok).toBe(true);
    if (peResult.ok) {
      expect(peResult.value.artifact.format).toBe("pe");
      expect(peResult.value.slices[0]?.architecture).toBeNull();
    }
  });
});
