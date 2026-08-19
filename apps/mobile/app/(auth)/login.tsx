import { useEffect, useState } from "react";
import { KeyboardAvoidingView, Platform, View } from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import { router } from "expo-router";
import * as Haptics from "expo-haptics";
import { Text } from "@/components/ui/text";
import { TextField } from "@/components/ui/text-field";
import { Button } from "@/components/ui/button";
import { MulticaLogo } from "@/components/brand/multica-logo";
import { useAuthStore } from "@/data/auth-store";
import { api } from "@/data/api";
import { mapAuthError } from "@/lib/auth-error";

export default function Login() {
  const loginWithPassword = useAuthStore((s) => s.loginWithPassword);
  const signupWithPassword = useAuthStore((s) => s.signupWithPassword);
  const [mode, setMode] = useState<"signin" | "signup">("signin");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [allowSignup, setAllowSignup] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Mobile has no config store; read the deployment's signup policy directly.
  // A failed fetch leaves the toggle visible — the server still enforces the
  // gate, so the worst case is a clean 403 rather than an unwanted account.
  useEffect(() => {
    let cancelled = false;
    api
      .getConfig()
      .then((cfg) => {
        if (!cancelled) setAllowSignup(cfg.allow_signup);
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, []);

  const onSubmit = async () => {
    const trimmed = email.trim();
    if (!trimmed || !password) return;
    if (mode === "signup" && password.length < 8) {
      setError("Password must be at least 8 characters.");
      return;
    }
    void Haptics.selectionAsync();
    setSubmitting(true);
    setError(null);
    try {
      if (mode === "signup") {
        await signupWithPassword(trimmed, password);
      } else {
        await loginWithPassword(trimmed, password);
      }
      router.replace("/");
    } catch (err) {
      void Haptics.notificationAsync(Haptics.NotificationFeedbackType.Error);
      setError(mapAuthError(err, "Couldn't sign you in. Try again."));
    } finally {
      setSubmitting(false);
    }
  };

  const toggleMode = () => {
    void Haptics.selectionAsync();
    setError(null);
    setMode((m) => (m === "signin" ? "signup" : "signin"));
  };

  return (
    <SafeAreaView className="flex-1 bg-background">
      <KeyboardAvoidingView
        className="flex-1"
        behavior={Platform.OS === "ios" ? "padding" : undefined}
      >
        <View className="flex-1 justify-center px-6 gap-6">
          <View className="items-center gap-3">
            <MulticaLogo size={32} />
            <View className="gap-1 items-center">
              <Text className="text-2xl font-semibold text-foreground">
                {mode === "signup" ? "Create your account" : "Sign in to Multica"}
              </Text>
              <Text className="text-sm text-muted-foreground text-center">
                {mode === "signup"
                  ? "Enter your email and choose a password."
                  : "Enter your email and password to continue."}
              </Text>
            </View>
          </View>

          <View className="gap-3">
            <TextField
              autoCapitalize="none"
              autoComplete="email"
              autoFocus
              keyboardType="email-address"
              placeholder="you@example.com"
              value={email}
              onChangeText={setEmail}
              editable={!submitting}
              invalid={!!error}
            />
            <TextField
              autoCapitalize="none"
              autoComplete={mode === "signup" ? "new-password" : "password"}
              secureTextEntry
              placeholder="Password"
              value={password}
              onChangeText={setPassword}
              onSubmitEditing={onSubmit}
              returnKeyType="go"
              editable={!submitting}
              invalid={!!error}
            />
            {error ? (
              <Text className="text-sm text-destructive">{error}</Text>
            ) : null}
          </View>

          <View className="gap-3">
            <Button
              size="lg"
              disabled={submitting || !email.trim() || !password}
              onPress={onSubmit}
            >
              <Text>
                {submitting
                  ? mode === "signup"
                    ? "Creating account..."
                    : "Signing in..."
                  : mode === "signup"
                    ? "Create account"
                    : "Sign in"}
              </Text>
            </Button>

            {allowSignup ? (
              <Button variant="ghost" disabled={submitting} onPress={toggleMode}>
                <Text>
                  {mode === "signup"
                    ? "Already have an account? Sign in"
                    : "Don't have an account? Create one"}
                </Text>
              </Button>
            ) : null}
          </View>
        </View>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}
