declare global {
  function qrcode(typeNumber: 0, errorCorrection: "M"): {
    addData(text: string): void;
    make(): void;
    createSvgTag(opts: { cellSize: number; margin: number }): string;
  };
}

export {};
