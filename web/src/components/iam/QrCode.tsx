import { useEffect, useState } from "react";
import QRCode from "qrcode";

/** Renders a value (e.g. an otpauth:// URI) as a scannable QR image. */
export function QrCode({ value, size = 176 }: { value: string; size?: number }) {
  const [dataUrl, setDataUrl] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    QRCode.toDataURL(value, { width: size, margin: 1 })
      .then((url) => alive && setDataUrl(url))
      .catch(() => alive && setDataUrl(null));
    return () => {
      alive = false;
    };
  }, [value, size]);

  if (!dataUrl) {
    return (
      <div
        className="rounded-md border border-[var(--border)] bg-[var(--muted)]/35"
        style={{ width: size, height: size }}
      />
    );
  }
  return (
    <img
      src={dataUrl}
      alt="MFA QR code"
      width={size}
      height={size}
      className="rounded-md border border-[var(--border)] bg-white p-1"
    />
  );
}
