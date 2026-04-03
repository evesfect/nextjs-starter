// lib/session.ts
import { SignJWT, jwtVerify } from "jose";
import { cookies } from "next/headers";

// Fail securely: Crash the app if the environment is misconfigured
if (!process.env.JWT_SECRET) {
  throw new Error("CRITICAL SECURITY ERROR: JWT_SECRET environment variable is missing.");
}

const secretKey = process.env.JWT_SECRET;
const encodedKey = new TextEncoder().encode(secretKey);

export async function createSession(userId: number) {
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

  // 1. Create the secure token
  const session = await new SignJWT({ userId, expiresAt })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime("7d")
    .sign(encodedKey);

  // 2. Set the secure HTTP-Only cookie
  const cookieStore = await cookies();
  cookieStore.set("session", session, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    expires: expiresAt,
    sameSite: "lax",
    path: "/",
  });
}

export async function getSession() {
  const cookieStore = await cookies();
  const session = cookieStore.get("session")?.value;
  if (!session) return null;

  try {
    const { payload } = await jwtVerify(session, encodedKey, {
      algorithms: ["HS256"],
    });
    return payload;
  } catch (error) {
    return null;
  }
}

export async function deleteSession() {
  const cookieStore = await cookies();
  cookieStore.delete("session");
}