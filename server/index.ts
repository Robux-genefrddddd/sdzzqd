import "dotenv/config";
import express from "express";
import cors from "cors";
import { handleDemo } from "./routes/demo";
import { handleGetIP, handleCheckVPN } from "./routes/ip-detection";
import { handleActivateLicense } from "./routes/license";
import { handleDailyReset } from "./routes/daily-reset";
import { handleAIChat } from "./routes/ai";
import {
  handleVerifyAdmin,
  handleBanUser,
  handleGetAllUsers,
  handleCreateLicense,
  handleBanIP,
  handleDeleteUser,
} from "./routes/admin";
import {
  handleCheckIPBan,
  handleCheckIPLimit,
  handleRecordUserIP,
  handleUpdateUserIPLogin,
} from "./routes/ip-management";
import {
  validateContentType,
  validateRequestSize,
  validateInput,
  rateLimit,
} from "./middleware/security";

export function createServer() {
  const app = express();

  // Trust proxy (for rate limiting to work correctly)
  app.set("trust proxy", 1);

  // Middleware - Order matters!
  // 1. CORS first (allow trusted origins)
  const corsOrigins = (process.env.CORS_ORIGINS || "")
    .split(",")
    .filter(Boolean);
  app.use(
    cors({
      origin: corsOrigins.length > 0 ? corsOrigins : true,
      credentials: true,
      methods: ["GET", "POST", "PUT", "DELETE"],
      allowedHeaders: ["Content-Type", "Authorization"],
    }),
  );

  // 2. Security headers
  app.use((req, res, next) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("X-XSS-Protection", "1; mode=block");
    res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
    res.setHeader("X-Content-Security-Policy", "default-src 'self'");
    res.setHeader(
      "Strict-Transport-Security",
      "max-age=31536000; includeSubDomains",
    );
    next();
  });

  // 3. Request size validation
  app.use(validateRequestSize);

  // 4. Parse JSON
  app.use(express.json({ limit: "10mb" }));
  app.use(express.urlencoded({ extended: true, limit: "10mb" }));

  // 5. Content-Type validation
  app.use(validateContentType);

  // 6. Input validation (check for suspicious patterns)
  app.use(validateInput);

  // 7. Rate limiting (general limit, stricter on admin routes)
  app.use(rateLimit(60000, 100)); // 100 requests per minute per IP

  // Create API router to handle all API routes
  const apiRouter = express.Router();

  // Example API routes
  apiRouter.get("/ping", (_req, res) => {
    const ping = process.env.PING_MESSAGE ?? "ping";
    res.json({ message: ping });
  });

  apiRouter.get("/demo", handleDemo);

  // IP detection routes
  apiRouter.get("/get-ip", handleGetIP);
  apiRouter.post("/check-vpn", handleCheckVPN);

  // IP management routes
  apiRouter.post("/check-ip-ban", handleCheckIPBan);
  apiRouter.post("/check-ip-limit", handleCheckIPLimit);
  apiRouter.post("/record-user-ip", handleRecordUserIP);
  apiRouter.post("/update-user-ip-login", handleUpdateUserIPLogin);

  // License activation route
  apiRouter.post("/activate-license", handleActivateLicense);

  // Daily reset route
  apiRouter.post("/daily-reset", handleDailyReset);

  // AI chat route
  apiRouter.post("/ai/chat", handleAIChat);

  // Admin routes (require authentication + stricter rate limiting)
  const adminRateLimit = rateLimit(60000, 10); // 10 requests per minute per IP
  apiRouter.post("/admin/verify", adminRateLimit, handleVerifyAdmin);
  apiRouter.post("/admin/ban-user", adminRateLimit, handleBanUser);
  apiRouter.post("/admin/ban-ip", adminRateLimit, handleBanIP);
  apiRouter.post("/admin/delete-user", adminRateLimit, handleDeleteUser);
  apiRouter.get("/admin/users", adminRateLimit, handleGetAllUsers);
  apiRouter.post("/admin/create-license", adminRateLimit, handleCreateLicense);

  // Mount API router
  app.use("/api", apiRouter);

  // 404 handler for API routes only
  app.use("/api", (_req, res) => {
    res.status(404).json({ error: "Not found" });
  });

  // Error handler
  app.use(
    (
      err: unknown,
      _req: express.Request,
      res: express.Response,
      _next: express.NextFunction,
    ) => {
      console.error("Unhandled error:", err);
      res.status(500).json({ error: "Internal server error" });
    },
  );

  return app;
}
