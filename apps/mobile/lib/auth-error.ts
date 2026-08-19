/**
 * Map backend auth errors to user-facing strings. The backend returns raw
 * English messages that are fine for logs but should not surface as-is —
 * we map the known shapes to friendlier copy and fall back to the caller's
 * default for anything unrecognised.
 */
export function mapAuthError(err: unknown, fallback: string): string {
  if (!(err instanceof Error)) return fallback;
  const msg = err.message.toLowerCase();
  if (/invalid email or password/.test(msg)) {
    return "That email and password don't match.";
  }
  if (/already exists/.test(msg)) {
    return "An account with that email already exists. Try signing in.";
  }
  if (/at least 8 characters/.test(msg)) {
    return "Password must be at least 8 characters.";
  }
  if (/rate.?limit|too many|throttle/.test(msg)) {
    return "Too many attempts. Wait a moment and try again.";
  }
  if (/network|fetch|timeout|unreachable/.test(msg)) {
    return "Can't reach Multica. Check your connection and retry.";
  }
  return fallback;
}
