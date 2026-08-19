import { redirect } from "next/navigation";

// The marketing site is gone: the product entry point is the login page,
// which forwards already-authenticated users on to their workspace via
// resolvePostAuthDestination.
export default function RootPage() {
  redirect("/login");
}
