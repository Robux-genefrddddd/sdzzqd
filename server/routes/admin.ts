import { RequestHandler } from "express";
import { z } from "zod";
import { initializeApp, cert } from "firebase-admin/app";
import { getFirestore } from "firebase-admin/firestore";
import { getAuth } from "firebase-admin/auth";

// Initialize Firebase Admin SDK (uses FIREBASE_SERVICE_ACCOUNT_KEY from env)
let adminDb: ReturnType<typeof getFirestore>;
let adminAuth: ReturnType<typeof getAuth>;

try {
  const serviceAccount = process.env.FIREBASE_SERVICE_ACCOUNT_KEY
    ? JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_KEY)
    : null;

  if (serviceAccount) {
    initializeApp({
      credential: cert(serviceAccount),
    });
    adminDb = getFirestore();
    adminAuth = getAuth();
  }
} catch (error) {
  console.error("Failed to initialize Firebase Admin:", error);
}

// Validation schemas
const VerifyAdminSchema = z.object({
  idToken: z.string().min(1, "ID token required"),
});

const UpdateUserAdminSchema = z.object({
  idToken: z.string().min(1, "ID token required"),
  targetUserId: z.string().uuid().or(z.string().min(10)),
  action: z.enum(["grant", "revoke"]),
});

const BanUserSchema = z.object({
  idToken: z.string().min(1, "ID token required"),
  userId: z.string().uuid().or(z.string().min(10)),
  reason: z.string().min(5).max(500),
  duration: z.number().int().positive(),
});

// Verify Firebase ID token and check admin status
async function verifyAdmin(idToken: string): Promise<string> {
  if (!adminAuth) throw new Error("Admin SDK not initialized");

  const decodedToken = await adminAuth.verifyIdToken(idToken);
  const userDoc = await adminDb.collection("users").doc(decodedToken.uid).get();

  if (!userDoc.exists || !userDoc.data()?.isAdmin) {
    throw new Error("Unauthorized: Not an admin");
  }

  return decodedToken.uid;
}

// Endpoint: Verify admin status
export const handleVerifyAdmin: RequestHandler = async (req, res) => {
  try {
    const { idToken } = VerifyAdminSchema.parse(req.body);
    const adminUid = await verifyAdmin(idToken);
    res.json({ success: true, adminUid });
  } catch (error) {
    console.error("Admin verification error:", error);
    res.status(401).json({
      error: "Unauthorized",
      details: error instanceof Error ? error.message : "Unknown error",
    });
  }
};

// Endpoint: Ban user (admin only)
export const handleBanUser: RequestHandler = async (req, res) => {
  try {
    const { idToken, userId, reason, duration } = BanUserSchema.parse(
      req.body,
    );
    const adminUid = await verifyAdmin(idToken);

    // Validate target user exists and is not an admin
    const targetUserDoc = await adminDb.collection("users").doc(userId).get();
    if (!targetUserDoc.exists) {
      return res.status(404).json({ error: "User not found" });
    }
    if (targetUserDoc.data()?.isAdmin) {
      return res.status(403).json({ error: "Cannot ban admin users" });
    }

    // Create ban record
    const banData = {
      userId,
      reason,
      bannedBy: adminUid,
      bannedAt: new Date(),
      duration,
      expiresAt: new Date(Date.now() + duration * 1000),
    };

    await adminDb.collection("bans").add(banData);

    // Log admin action
    console.log(`[ADMIN] ${adminUid} banned user ${userId}. Reason: ${reason}`);

    res.json({ success: true, message: "User banned successfully" });
  } catch (error) {
    console.error("Ban user error:", error);
    res.status(400).json({
      error: "Failed to ban user",
      details: error instanceof Error ? error.message : "Unknown error",
    });
  }
};

// Endpoint: Get all users (admin only)
export const handleGetAllUsers: RequestHandler = async (req, res) => {
  try {
    const idToken = req.headers.authorization?.split("Bearer ")[1];
    if (!idToken) throw new Error("No ID token provided");

    await verifyAdmin(idToken);

    const snapshot = await adminDb.collection("users").get();
    const users = snapshot.docs.map((doc) => ({
      uid: doc.id,
      email: doc.data().email,
      displayName: doc.data().displayName,
      isAdmin: doc.data().isAdmin,
      plan: doc.data().plan,
      createdAt: doc.data().createdAt,
    }));

    res.json({ success: true, users });
  } catch (error) {
    console.error("Get users error:", error);
    res.status(401).json({
      error: "Unauthorized",
      details: error instanceof Error ? error.message : "Unknown error",
    });
  }
};

// Endpoint: Create license (admin only)
export const handleCreateLicense: RequestHandler = async (req, res) => {
  try {
    const idToken = req.headers.authorization?.split("Bearer ")[1];
    if (!idToken) throw new Error("No ID token provided");

    const adminUid = await verifyAdmin(idToken);

    const { plan, validityDays } = z
      .object({
        plan: z.enum(["Free", "Classic", "Pro"]),
        validityDays: z.number().int().positive(),
      })
      .parse(req.body);

    // Generate unique license key
    const licenseKey = `LIC-${Date.now()}-${Math.random().toString(36).substr(2, 9).toUpperCase()}`;

    const licenseData = {
      key: licenseKey,
      plan,
      validityDays,
      createdBy: adminUid,
      createdAt: new Date(),
      used: false,
      usedBy: null,
      usedAt: null,
    };

    await adminDb.collection("licenses").doc(licenseKey).set(licenseData);

    console.log(`[ADMIN] ${adminUid} created license ${licenseKey}`);

    res.json({ success: true, licenseKey });
  } catch (error) {
    console.error("Create license error:", error);
    res.status(400).json({
      error: "Failed to create license",
      details: error instanceof Error ? error.message : "Unknown error",
    });
  }
};
