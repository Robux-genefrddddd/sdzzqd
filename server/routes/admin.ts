import { RequestHandler } from "express";
import { z } from "zod";
import {
  initializeFirebaseAdmin,
  FirebaseAdminService,
} from "../lib/firebase-admin";

// Initialize on first use
initializeFirebaseAdmin();

// Validation schemas with strict constraints
const VerifyAdminSchema = z.object({
  idToken: z
    .string()
    .min(10)
    .max(3000)
    .regex(/^[A-Za-z0-9_\-\.]+$/, "Invalid token format"),
});

const BanUserSchema = z.object({
  idToken: z
    .string()
    .min(10)
    .max(3000)
    .regex(/^[A-Za-z0-9_\-\.]+$/, "Invalid token format"),
  userId: z.string().min(10).max(100),
  reason: z.string().min(5).max(500).trim(),
  duration: z.number().int().min(1).max(36500),
});

const CreateLicenseSchema = z.object({
  idToken: z
    .string()
    .min(10)
    .max(3000)
    .regex(/^[A-Za-z0-9_\-\.]+$/, "Invalid token format"),
  plan: z.enum(["Free", "Classic", "Pro"]),
  validityDays: z.number().int().min(1).max(3650),
});

const BanIPSchema = z.object({
  idToken: z
    .string()
    .min(10)
    .max(3000)
    .regex(/^[A-Za-z0-9_\-\.]+$/, "Invalid token format"),
  ipAddress: z
    .string()
    .ip({ version: "v4" })
    .or(z.string().ip({ version: "v6" })),
  reason: z.string().min(5).max(500).trim(),
  duration: z.number().int().min(1).max(36500),
});

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
