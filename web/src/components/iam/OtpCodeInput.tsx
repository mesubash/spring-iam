import { REGEXP_ONLY_DIGITS } from "input-otp";

import { InputOTP, InputOTPGroup, InputOTPSlot } from "@/components/ui/input-otp";
import { Label } from "@/components/ui/label";
import { cn } from "@/lib/utils";

type OtpCodeInputProps = {
  value: string;
  onValueChange: (value: string) => void;
  onComplete?: (value: string) => void;
  disabled?: boolean;
  autoFocus?: boolean;
  id?: string;
  label?: string;
  className?: string;
  invalid?: boolean;
  onInvalidReset?: () => void;
};

export function OtpCodeInput({
  value,
  onValueChange,
  onComplete,
  disabled,
  autoFocus,
  id,
  label = "Enter verification code",
  className,
  invalid,
  onInvalidReset,
}: OtpCodeInputProps) {
  const resetInvalidState = () => {
    if (!invalid) return;
    onValueChange("");
    onInvalidReset?.();
  };

  const handleChange = (nextValue: string) => {
    if (invalid) {
      resetInvalidState();
      return;
    }
    onValueChange(nextValue.replace(/\D/g, "").slice(0, 6));
  };

  const handleComplete = (nextValue: string) => {
    const code = nextValue.replace(/\D/g, "").slice(0, 6);
    if (code.length === 6) onComplete?.(code);
  };

  return (
    <div className={cn("space-y-2.5", className)}>
      <Label htmlFor={id} className="block text-center text-xs font-medium text-muted-foreground">
        {label}
      </Label>
      <InputOTP
        id={id}
        maxLength={6}
        value={value}
        onChange={handleChange}
        onComplete={handleComplete}
        pattern={REGEXP_ONLY_DIGITS}
        autoFocus={autoFocus}
        disabled={disabled}
        aria-invalid={invalid || undefined}
        containerClassName={cn("justify-center", invalid && "animate-otp-shake")}
        onFocus={resetInvalidState}
        onPointerDown={resetInvalidState}
        onKeyDown={(event) => {
          if (!invalid) return;
          if (event.key === "Backspace" || event.key === "Delete") {
            event.preventDefault();
            resetInvalidState();
            return;
          }
          if (event.key.length !== 1 || !/\d/.test(event.key)) return;
          event.preventDefault();
          onValueChange(event.key);
          onInvalidReset?.();
        }}
      >
        <InputOTPGroup>
          {Array.from({ length: 6 }).map((_, index) => (
            <InputOTPSlot
              key={index}
              index={index}
              className={
                invalid
                  ? "border-destructive/60 bg-destructive/5 text-destructive ring-1 ring-destructive/20"
                  : undefined
              }
            />
          ))}
        </InputOTPGroup>
      </InputOTP>
    </div>
  );
}
