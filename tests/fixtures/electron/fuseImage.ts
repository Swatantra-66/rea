import {
  ELECTRON_FUSE_SENTINEL,
  ELECTRON_FUSE_STATE_BYTES,
} from "../../../src/domain/electron/electronFuses.js";

export const FUSE_SENTINEL = Buffer.from(ELECTRON_FUSE_SENTINEL, "ascii");

/** Obsidian's observed version-1 states: disabled, enabled, then six more with the last enabled. */
export const OBSIDIAN_FUSE_BYTES = [
  ELECTRON_FUSE_STATE_BYTES.disabled,
  ELECTRON_FUSE_STATE_BYTES.enabled,
  ELECTRON_FUSE_STATE_BYTES.disabled,
  ELECTRON_FUSE_STATE_BYTES.disabled,
  ELECTRON_FUSE_STATE_BYTES.disabled,
  ELECTRON_FUSE_STATE_BYTES.disabled,
  ELECTRON_FUSE_STATE_BYTES.disabled,
  ELECTRON_FUSE_STATE_BYTES.enabled,
] as const;

export const fuseWire = (version: number, fuses: readonly number[]): Buffer =>
  Buffer.from([version, fuses.length, ...fuses]);

export const thinMacho = (cpuType: number, body: Buffer): Buffer => {
  const header = Buffer.alloc(32);
  header.writeUInt32LE(0xfeedfacf, 0);
  header.writeUInt32LE(cpuType, 4);
  header.writeUInt32LE(0, 8);
  header.writeUInt32LE(2, 12);
  return Buffer.concat([header, body]);
};

export const thinFuseImage = (
  fuses: readonly number[],
  version = 1,
): { readonly bytes: Buffer; readonly sentinelOffset: number } => ({
  bytes: thinMacho(
    0x0100000c,
    Buffer.concat([FUSE_SENTINEL, fuseWire(version, fuses)]),
  ),
  sentinelOffset: 32,
});

export const universalFuseImage = (): {
  readonly bytes: Buffer;
  readonly left: {
    readonly fileOffset: number;
    readonly sentinelOffset: number;
  };
  readonly right: {
    readonly fileOffset: number;
    readonly sentinelOffset: number;
  };
} => {
  const left = thinMacho(
    0x01000007,
    Buffer.concat([FUSE_SENTINEL, fuseWire(1, OBSIDIAN_FUSE_BYTES)]),
  );
  const rightFuses = [...OBSIDIAN_FUSE_BYTES];
  rightFuses[3] = ELECTRON_FUSE_STATE_BYTES.enabled;
  const right = thinMacho(
    0x0100000c,
    Buffer.concat([FUSE_SENTINEL, fuseWire(1, rightFuses)]),
  );
  const tableEnd = 48;
  const table = Buffer.alloc(tableEnd);
  table.writeUInt32BE(0xcafebabe, 0);
  table.writeUInt32BE(2, 4);
  const writeEntry = (
    index: number,
    cpuType: number,
    offset: number,
    size: number,
  ) => {
    const base = 8 + index * 20;
    table.writeUInt32BE(cpuType, base);
    table.writeUInt32BE(0, base + 4);
    table.writeUInt32BE(offset, base + 8);
    table.writeUInt32BE(size, base + 12);
    table.writeUInt32BE(0, base + 16);
  };
  writeEntry(0, 0x01000007, tableEnd, left.length);
  writeEntry(1, 0x0100000c, tableEnd + left.length, right.length);
  return {
    bytes: Buffer.concat([table, left, right]),
    left: { fileOffset: tableEnd, sentinelOffset: tableEnd + 32 },
    right: {
      fileOffset: tableEnd + left.length,
      sentinelOffset: tableEnd + left.length + 32,
    },
  };
};

export const peFuseImage = (
  fuses: readonly number[],
): { readonly bytes: Buffer; readonly sentinelOffset: number } => {
  const header = Buffer.alloc(0x80);
  header.write("MZ", 0, "ascii");
  header.writeUInt32LE(0x80, 0x3c);
  const body = Buffer.concat([
    Buffer.from("PE\0\0", "binary"),
    FUSE_SENTINEL,
    fuseWire(1, fuses),
  ]);
  return { bytes: Buffer.concat([header, body]), sentinelOffset: 0x84 };
};

export const elfFuseImage = (
  fuses: readonly number[],
  version = 1,
): { readonly bytes: Buffer; readonly sentinelOffset: number } => ({
  bytes: Buffer.concat([
    Buffer.from([0x7f, 0x45, 0x4c, 0x46]),
    FUSE_SENTINEL,
    fuseWire(version, fuses),
  ]),
  sentinelOffset: 4,
});

export const truncatedFuseImage = (): Buffer =>
  thinMacho(
    0x0100000c,
    Buffer.concat([FUSE_SENTINEL, Buffer.from([1, 4, 0x31])]),
  );

export const twoSentinelElf = (): {
  readonly bytes: Buffer;
  readonly offsets: readonly [number, number];
} => {
  const wire = fuseWire(1, OBSIDIAN_FUSE_BYTES);
  const first = 4;
  const second = first + FUSE_SENTINEL.length + wire.length + 2;
  return {
    bytes: Buffer.concat([
      Buffer.from([0x7f, 0x45, 0x4c, 0x46]),
      FUSE_SENTINEL,
      wire,
      Buffer.from([0, 0]),
      FUSE_SENTINEL,
      wire,
    ]),
    offsets: [first, second],
  };
};

export const sentinelFreeMacho = (): Buffer =>
  thinMacho(0x0100000c, Buffer.from("no fuse wire in this image"));

export const structuredElfFuseImage = (
  machine: number,
  fuses: readonly number[],
  class_ = 2,
  endian = 1,
): { readonly bytes: Buffer; readonly sentinelOffset: number } => {
  const header = Buffer.alloc(class_ === 1 ? 52 : 64);
  header.set([0x7f, 0x45, 0x4c, 0x46, class_, endian, 1]);
  if (endian === 1) {
    header.writeUInt16LE(machine, 18);
    header.writeUInt32LE(1, 20);
    header.writeUInt16LE(class_ === 1 ? 52 : 64, class_ === 1 ? 40 : 52);
  } else {
    header.writeUInt16BE(machine, 18);
    header.writeUInt32BE(1, 20);
    header.writeUInt16BE(class_ === 1 ? 52 : 64, class_ === 1 ? 40 : 52);
  }
  return {
    bytes: Buffer.concat([header, FUSE_SENTINEL, fuseWire(1, fuses)]),
    sentinelOffset: header.length,
  };
};

export const structuredPeFuseImage = (
  machine: number,
  fuses: readonly number[],
  offset = 0x80,
): { readonly bytes: Buffer; readonly sentinelOffset: number } => {
  const header = Buffer.alloc(offset);
  header.write("MZ", 0, "ascii");
  header.writeUInt32LE(offset, 0x3c);
  const peHeader = Buffer.alloc(6);
  peHeader.write("PE\0\0", 0, "binary");
  peHeader.writeUInt16LE(machine, 4);
  const body = Buffer.concat([peHeader, FUSE_SENTINEL, fuseWire(1, fuses)]);
  return {
    bytes: Buffer.concat([header, body]),
    sentinelOffset: offset + peHeader.length,
  };
};
