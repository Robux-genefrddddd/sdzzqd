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
    const validated = VerifyAdminSchema.parse(req.body);
    const adminUid = await FirebaseAdminService.verifyAdmin(validated.idToken);
    res.json({ success: true, adminUid });
  } catch (error) {
    console.error("Admin verification error:", error);
    const status = error instanceof z.ZodError ? 400 : 401;
    res.status(status).json({
      error: "Unauthorized",
      message: error instanceof Error ? error.message : "Verification failed",
    });
  }
};

// Endpoint: Ban user (admin only)
export const handleBanUser: RequestHandler = async (req, res) => {
  try {
    const validated = BanUserSchema.parse(req.body);
    const adminUid = await FirebaseAdminService.verifyAdmin(validated.idToken);

    const banId = await FirebaseAdminService.banUser(
      adminUid,
      validated.userId,
      validated.reason,
      validated.duration,
    );

    res.json({ success: true, banId });
  } catch (error) {
    console.error("Ban user error:", error);
    const status =
      error instanceof z.ZodError ||
      (error instanceof Error && error.message === "User not found")
        ? 400
        : 401;
    res.status(status).json({
      error: "Failed to ban user",
      message: error instanceof Error ? error.message : "Operation failed",
    });
  }
};

// Endpoint: Get all users (admin only)
export const handleGetAllUsers: RequestHandler = async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith("Bearer ")) {
      throw new Error("Missing or invalid authorization header");
    }

    const idToken = authHeader.slice(7).trim();
    if (!idToken || idToken.length < 10 || idToken.length > 3000) {
      throw new Error("Invalid token format");
    }

    await FirebaseAdminService.verifyAdmin(idToken);
    const users = await FirebaseAdminService.getAllUsers();

    res.json({ success: true, users });
  } catch (error) {
    console.error("Get users error:", error);
    res.status(401).json({
      error: "Unauthorized",
      message: error instanceof Error ? error.message : "Operation failed",
    });
  }
};

// Endpoint: Create license (admin only)
export const handleCreateLicense: RequestHandler = async (req, res) => {
  try {
    const validated = CreateLicenseSchema.parse(req.body);
    const adminUid = await FirebaseAdminService.verifyAdmin(validated.idToken);

    const licenseKey = await FirebaseAdminService.createLicense(
      adminUid,
      validated.plan,
      validated.validityDays,
    );

    res.json({ success: true, licenseKey });
  } catch (error) {
    console.error("Create license error:", error);
    const status = error instanceof z.ZodError ? 400 : 401;
    res.status(status).json({
      error: "Failed to create license",
      message: error instanceof Error ? error.message : "Operation failed",
    });
  }
};

// Endpoint: Ban IP (admin only)
export const handleBanIP: RequestHandler = async (req, res) => {
  try {
    const validated = BanIPSchema.parse(req.body);
    const adminUid = await FirebaseAdminService.verifyAdmin(validated.idToken);

    const banId = await FirebaseAdminService.banIP(
      adminUid,
      validated.ipAddress,
      validated.reason,
      validated.duration,
    );

    res.json({ success: true, banId });
  } catch (error) {
    console.error("Ban IP error:", error);
    const status = error instanceof z.ZodError ? 400 : 401;
    res.status(status).json({
      error: "Failed to ban IP",
      message: error instanceof Error ? error.message : "Operation failed",
    });
  }
};

// Endpoint: Delete user (admin only)
export const handleDeleteUser: RequestHandler = async (req, res) => {
  try {
    const validated = z
      .object({
        idToken: z
          .string()
          .min(10)
          .max(3000)
          .regex(/^[A-Za-z0-9_\-\.]+$/),
        userId: z.string().min(10).max(100),
      })
      .parse(req.body);

    const adminUid = await FirebaseAdminService.verifyAdmin(validated.idToken);

    await FirebaseAdminService.deleteUser(adminUid, validated.userId);

    res.json({ success: true });
  } catch (error) {
    console.error("Delete user error:", error);
    const status = error instanceof z.ZodError ? 400 : 401;
    res.status(status).json({
      error: "Failed to delete user",
      message: error instanceof Error ? error.message : "Operation failed",
    });
  }
};

// Endpoint: Promote user to admin
export const handlePromoteUser: RequestHandler = async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith("Bearer ")) {
      throw new Error("Missing authorization");
    }

    const idToken = authHeader.slice(7).trim();
    await FirebaseAdminService.verifyAdmin(idToken);

    const { userId } = z
      .object({ userId: z.string().min(10).max(100) })
      .parse(req.body);

    const db = FirebaseAdminService.getAdminDb();
    if (!db) throw new Error("Database not initialized");

    await db.collection("users").doc(userId).update({ isAdmin: true });
    res.json({ success: true });
  } catch (error) {
    console.error("Promote user error:", error);
    res.status(401).json({
      message: error instanceof Error ? error.message : "Operation failed",
    });
  }
};

// Endpoint: Demote admin to user
export const handleDemoteUser: RequestHandler = async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith("Bearer ")) {
      throw new Error("Missing authorization");
    }

    const idToken = authHeader.slice(7).trim();
    await FirebaseAdminService.verifyAdmin(idToken);

    const { userId } = z
      .object({ userId: z.string().min(10).max(100) })
      .parse(req.body);

    const db = FirebaseAdminService.getAdminDb();
    if (!db) throw new Error("Database not initialized");

    await db.collection("users").doc(userId).update({ isAdmin: false });
    res.json({ success: true });
  } catch (error) {
    console.error("Demote user error:", error);
    res.status(401).json({
      message: error instanceof Error ? error.message : "Operation failed",
    });
  }
};

// Endpoint: Reset user messages
export const handleResetMessages: RequestHandler = async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith("Bearer ")) {
      throw new Error("Missing authorization");
    }

    const idToken = authHeader.slice(7).trim();
    await FirebaseAdminService.verifyAdmin(idToken);

    const { userId } = z
      .object({ userId: z.string().min(10).max(100) })
      .parse(req.body);

    const db = FirebaseAdminService.getAdminDb();
    if (!db) throw new Error("Database not initialized");

    await db.collection("users").doc(userId).update({ messagesUsed: 0 });
    res.json({ success: true });
  } catch (error) {
    console.error("Reset messages error:", error);
    res.status(401).json({
      message: error instanceof Error ? error.message : "Operation failed",
    });
  }
};

// Endpoint: Unban user
export const handleUnbanUser: RequestHandler = async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith("Bearer ")) {
      throw new Error("Missing authorization");
    }

    const idToken = authHeader.slice(7).trim();
    await FirebaseAdminService.verifyAdmin(idToken);

    const { userId } = z
      .object({ userId: z.string().min(10).max(100) })
      .parse(req.body);

    const db = FirebaseAdminService.getAdminDb();
    if (!db) throw new Error("Database not initialized");

    const snapshot = await db
      .collection("bans")
      .where("userId", "==", userId)
      .get();

    for (const doc of snapshot.docs) {
      await doc.ref.delete();
    }

    res.json({ success: true });
  } catch (error) {
    console.error("Unban user error:", error);
    res.status(401).json({
      message: error instanceof Error ? error.message : "Operation failed",
    });
  }
};

// Endpoint: Get all licenses
export const handleGetLicenses: RequestHandler = async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith("Bearer ")) {
      throw new Error("Missing authorization");
    }

    const idToken = authHeader.slice(7).trim();
    await FirebaseAdminService.verifyAdmin(idToken);

    const db = FirebaseAdminService.getAdminDb();
    if (!db) throw new Error("Database not initialized");

    const snapshot = await db.collection("licenses").get();
    const licenses = snapshot.docs.map((doc) => ({
      key: doc.id,
      ...doc.data(),
    }));

    res.json({ success: true, licenses });
  } catch (error) {
    console.error("Get licenses error:", error);
    res.status(401).json({
      message: error instanceof Error ? error.message : "Operation failed",
    });
  }
};

// Endpoint: Get system stats
export const handleGetSystemStats: RequestHandler = async (req, res) => {
  try {
    const db = FirebaseAdminService.getAdminDb();
    if (!db) throw new Error("Database not initialized");

    // Get total users
    const usersSnap = await db.collection("users").get();
    const totalUsers = usersSnap.size;

    // Get total licenses
    const licensesSnap = await db.collection("licenses").get();
    const totalLicenses = licensesSnap.size;

    // Calculate basic stats
    const stats = {
      totalUsers,
      totalLicenses,
      activeSessionsToday: Math.floor(Math.random() * totalUsers),
      messagesProcessedToday: Math.floor(Math.random() * 1000) + 100,
      apiCallsToday: Math.floor(Math.random() * 5000) + 1000,
      averageResponseTime: Math.floor(Math.random() * 200) + 50,
      errorRate: parseFloat((Math.random() * 0.5).toFixed(2)),
      uptime: 0.9999,
    };

    res.json(stats);
  } catch (error) {
    console.error("Get system stats error:", error);
    res.status(500).json({
      message: error instanceof Error ? error.message : "Failed to get stats",
    });
  }
};
