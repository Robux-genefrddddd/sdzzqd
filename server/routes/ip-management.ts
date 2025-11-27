import { RequestHandler } from "express";
import { z } from "zod";
import {
  getAdminDb,
  initializeFirebaseAdmin,
  isAdminInitialized,
} from "../lib/firebase-admin";
import { Timestamp } from "firebase-admin/firestore";

// Initialize Firebase Admin on module load
initializeFirebaseAdmin();

/**
 * Validation schemas for IP management endpoints
 */
const IPAddressSchema = z
  .string()
  .ip({ version: "v4" })
  .or(z.string().ip({ version: "v6" }));

const CheckIPBanSchema = z.object({
  ipAddress: IPAddressSchema,
});

const CheckIPLimitSchema = z.object({
  ipAddress: IPAddressSchema,
  maxAccounts: z.number().int().min(1).max(10),
});

const RecordUserIPSchema = z.object({
  userId: z
    .string()
    .min(20)
    .max(40)
    .regex(/^[a-zA-Z0-9]{20,40}$/),
  ipAddress: IPAddressSchema,
  email: z.string().email().optional(),
});

const UpdateUserIPLoginSchema = z.object({
  userId: z
    .string()
    .min(20)
    .max(40)
    .regex(/^[a-zA-Z0-9]{20,40}$/),
  ipAddress: IPAddressSchema,
});

export interface IPBan {
  id: string;
  ipAddress: string;
  reason: string;
  bannedAt: any;
  expiresAt?: any;
}

export interface UserIP {
  id: string;
  userId: string;
  ipAddress: string;
  email: string;
  recordedAt: any;
  lastUsed: any;
}

export const handleCheckIPBan: RequestHandler = async (req, res) => {
  try {
    // Validate input
    const validated = CheckIPBanSchema.parse(req.body);
    const { ipAddress } = validated;

    // If Firebase Admin is not initialized, return no ban
    if (!isAdminInitialized()) {
      console.warn(
        "Firebase Admin not initialized. Set FIREBASE_SERVICE_ACCOUNT_KEY env var for IP ban checking.",
      );
      return res.json({ banned: false });
    }

    const db = getAdminDb();
    if (!db) {
      return res.json({ banned: false });
    }

    const snapshot = await db
      .collection("ip_bans")
      .where("ipAddress", "==", ipAddress)
      .get();

    if (snapshot.empty) {
      return res.json({ banned: false });
    }

    const banDoc = snapshot.docs[0];
    const banData = banDoc.data() as IPBan;

    // Check if ban has expired
    if (banData.expiresAt) {
      const expiresAt = banData.expiresAt.toDate();
      if (new Date() > expiresAt) {
        // Ban has expired, delete it
        await banDoc.ref.delete();
        return res.json({ banned: false });
      }
    }

    return res.json({
      banned: true,
      reason: banData.reason,
      expiresAt: banData.expiresAt ? banData.expiresAt.toDate() : null,
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({
        error: "Invalid IP address format",
        details: error.errors,
      });
    }
    console.error("Error checking IP ban:", error);
    return res.status(500).json({ error: "Failed to check IP ban" });
  }
};

export const handleCheckIPLimit: RequestHandler = async (req, res) => {
  try {
    // Validate input
    const validated = CheckIPLimitSchema.parse(req.body);
    const { ipAddress, maxAccounts } = validated;

    // If Firebase Admin is not initialized, return no limit exceeded
    if (!isAdminInitialized()) {
      console.warn(
        "Firebase Admin not initialized. Set FIREBASE_SERVICE_ACCOUNT_KEY env var for IP limit checking.",
      );
      return res.json({
        accountCount: 0,
        maxAccounts,
        isLimitExceeded: false,
      });
    }

    const db = getAdminDb();
    if (!db) {
      return res.json({
        accountCount: 0,
        maxAccounts,
        isLimitExceeded: false,
      });
    }

    const snapshot = await db
      .collection("user_ips")
      .where("ipAddress", "==", ipAddress)
      .get();

    const accountCount = snapshot.size;
    const isLimitExceeded = accountCount >= maxAccounts;

    return res.json({
      accountCount,
      maxAccounts,
      isLimitExceeded,
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({
        error: "Invalid request parameters",
        details: error.errors,
      });
    }
    console.error("Error checking IP limit:", error);
    return res.status(500).json({ error: "Failed to check IP limit" });
  }
};

export const handleRecordUserIP: RequestHandler = async (req, res) => {
  try {
    // Validate input
    const validated = RecordUserIPSchema.parse(req.body);
    const { userId, email, ipAddress } = validated;

    // If Firebase Admin is not initialized, skip recording
    if (!isAdminInitialized()) {
      console.warn(
        "Firebase Admin not initialized. Skipping IP recording. Set FIREBASE_SERVICE_ACCOUNT_KEY env var.",
      );
      return res.json({ success: true, ipId: "pending-initialization" });
    }

    const db = getAdminDb();
    if (!db) {
      return res.json({ success: true, ipId: "pending-initialization" });
    }

    const now = Timestamp.now();

    const docRef = await db.collection("user_ips").add({
      userId,
      email: email || "",
      ipAddress,
      recordedAt: now,
      lastUsed: now,
    });

    return res.json({ success: true, ipId: docRef.id });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({
        error: "Invalid request parameters",
        details: error.errors,
      });
    }
    console.error("Error recording user IP:", error);
    return res.status(500).json({ error: "Failed to record IP" });
  }
};

export const handleUpdateUserIPLogin: RequestHandler = async (req, res) => {
  try {
    // Validate input
    const validated = UpdateUserIPLoginSchema.parse(req.body);
    const { userId, ipAddress } = validated;

    // If Firebase Admin is not initialized, skip updating
    if (!isAdminInitialized()) {
      console.warn(
        "Firebase Admin not initialized. Skipping IP login update. Set FIREBASE_SERVICE_ACCOUNT_KEY env var.",
      );
      return res.json({ success: true });
    }

    const db = getAdminDb();
    if (!db) {
      return res.json({ success: true });
    }

    const snapshot = await db
      .collection("user_ips")
      .where("userId", "==", userId)
      .get();

    let found = false;
    for (const doc of snapshot.docs) {
      if (doc.data().ipAddress === ipAddress) {
        // Update last used
        await doc.ref.update({
          lastUsed: Timestamp.now(),
        });
        found = true;
        break;
      }
    }

    if (!found) {
      // Record new IP
      await db.collection("user_ips").add({
        userId,
        ipAddress,
        recordedAt: Timestamp.now(),
        lastUsed: Timestamp.now(),
      });
    }

    return res.json({ success: true });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({
        error: "Invalid request parameters",
        details: error.errors,
      });
    }
    console.error("Error updating user IP login:", error);
    return res.status(500).json({ error: "Failed to update IP login" });
  }
};
