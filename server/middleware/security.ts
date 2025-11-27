import { Request, Response, NextFunction } from "express";
import { z } from "zod";

/**
 * Content-Type validation middleware.
 * Ensures requests have valid content types.
 */
export function validateContentType(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  const contentType = req.get("content-type");

  // Allow JSON requests
  if (req.method === "POST" || req.method === "PUT") {
    if (!contentType?.includes("application/json")) {
      return res.status(400).json({
        error: "Invalid Content-Type. Must be application/json.",
      });
    }
  }

  next();
}

/**
 * Request body size limit to prevent buffer overflow attacks.
 */
export function validateRequestSize(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  const maxSize = 10 * 1024 * 1024; // 10MB

  if (req.headers["content-length"]) {
    const contentLength = parseInt(req.headers["content-length"]);
    if (contentLength > maxSize) {
      return res.status(413).json({
        error: "Request body too large.",
      });
    }
  }

  next();
}

/**
 * Input validation middleware.
 * Checks request body for suspicious patterns and injection attempts.
 */
export function validateInput(req: Request, res: Response, next: NextFunction) {
  if (!req.body || typeof req.body !== "object") {
    return next();
  }

  // Check for null bytes in all string values
  const hasNullBytes = (obj: unknown): boolean => {
    if (typeof obj === "string") {
      return obj.includes("\0");
    }
    if (typeof obj === "object" && obj !== null) {
      return Object.values(obj).some(hasNullBytes);
    }
    return false;
  };

  if (hasNullBytes(req.body)) {
    return res.status(400).json({
      error: "Invalid input: null bytes detected.",
    });
  }

  // Check for excessively long strings (prevent DoS)
  const checkStringLength = (obj: unknown, maxLength = 10000): boolean => {
    if (typeof obj === "string" && obj.length > maxLength) {
      return true;
    }
    if (typeof obj === "object" && obj !== null) {
      return Object.values(obj).some((val) =>
        checkStringLength(val, maxLength),
      );
    }
    return false;
  };

  if (checkStringLength(req.body)) {
    return res.status(400).json({
      error: "Invalid input: string too long.",
    });
  }

  next();
}

/**
 * Server-side rate limiting using in-memory store.
 * Tracks requests per user ID (from JWT) with priority, falls back to IP address.
 * For production, use Redis or similar persistent store.
 */
const rateLimitStore = new Map<string, Array<{ timestamp: number }>>();

export function serverRateLimit(
  windowMs: number = 60000,
  maxRequests: number = 100,
) {
  return (req: Request, res: Response, next: NextFunction) => {
    // Priority: use decoded UID > use IP address
    let userIdentifier: string;

    if ((req as any).decodedUid) {
      // User is authenticated, use their UID for rate limiting
      userIdentifier = `uid:${(req as any).decodedUid}`;
    } else if ((req as any).userId) {
      // Fallback to userId if available
      userIdentifier = `uid:${(req as any).userId}`;
    } else {
      // Fall back to IP address for unauthenticated requests
      userIdentifier =
        `ip:${(req.headers["x-forwarded-for"] as string)?.split(",")[0]}` ||
        `ip:${req.headers["x-real-ip"]}` ||
        `ip:${req.ip}` ||
        `ip:${req.socket.remoteAddress}` ||
        "unknown";
    }

    const key = `ratelimit:${userIdentifier}:${req.path}`;
    const now = Date.now();

    // Initialize or get existing request timestamps
    let requests = rateLimitStore.get(key) || [];

    // Remove old requests outside the window
    requests = requests.filter((req) => now - req.timestamp < windowMs);

    // Check if limit exceeded
    if (requests.length >= maxRequests) {
      const oldestRequest = requests[0];
      const retryAfter = Math.ceil(
        (windowMs - (now - oldestRequest.timestamp)) / 1000,
      );

      return res.status(429).json({
        error: "Too many requests. Please try again later.",
        retryAfter,
      });
    }

    // Add current request
    requests.push({ timestamp: now });
    rateLimitStore.set(key, requests);

    // Store on request object for downstream use
    (req as any).rateLimitRemaining = maxRequests - requests.length;

    next();
  };
}

/**
 * Authentication middleware - extracts and validates JWT token from request.
 * Decodes JWT claims without verifying signature (signature verified later by routes).
 */
export function authMiddleware(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  const idToken =
    req.body?.idToken ||
    (req.headers.authorization?.startsWith("Bearer ")
      ? req.headers.authorization.slice(7)
      : null);

  if (!idToken) {
    // Store null and continue (route handlers will check for auth)
    (req as any).idToken = null;
    (req as any).decodedUid = null;
    return next();
  }

  // Store token on request for later verification
  (req as any).idToken = idToken;

  // Try to extract UID from JWT for rate limiting purposes
  // This is not a security verification - the actual route will verify the signature
  try {
    // Firebase JWT format: header.payload.signature
    const parts = idToken.split(".");
    if (parts.length === 3) {
      const payload = JSON.parse(
        Buffer.from(parts[1], "base64").toString("utf-8"),
      );
      if (payload.uid) {
        (req as any).decodedUid = payload.uid;
      }
    }
  } catch (error) {
    // If parsing fails, just continue - signature verification will catch invalid tokens
  }

  next();
}

/**
 * CORS origin validation.
 * Restricts requests to allowed origins.
 */
export function validateOrigin(allowedOrigins: string[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    const origin = req.headers.origin;

    if (!origin || !allowedOrigins.includes(origin)) {
      console.warn(
        `[SECURITY] Blocked request from unauthorized origin: ${origin}`,
      );
      return res.status(403).json({
        error: "Forbidden: Invalid origin.",
      });
    }

    next();
  };
}

/**
 * ID Token validation schema.
 * Ensures ID tokens follow expected format.
 */
export const IdTokenSchema = z
  .string()
  .min(10, "Token too short")
  .max(3000, "Token too long")
  .regex(/^[A-Za-z0-9_\-\.]+$/, "Invalid token format");

/**
 * Firebase UID validation schema.
 */
export const FirebaseUidSchema = z
  .string()
  .min(20, "Invalid user ID")
  .max(40, "Invalid user ID")
  .regex(/^[a-zA-Z0-9]{20,40}$/, "Invalid user ID format");

/**
 * Generic input validation using Zod.
 */
export function validateRequestBody<T>(schema: z.ZodSchema<T>) {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      const validated = schema.parse(req.body);
      req.body = validated;
      next();
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({
          error: "Invalid request body",
          details: error.errors.map((e) => ({
            field: e.path.join("."),
            message: e.message,
          })),
        });
      }
      res.status(400).json({
        error: "Invalid request body",
      });
    }
  };
}

/**
 * SQL injection detection (for defense-in-depth).
 * Detects common SQL injection patterns.
 */
export function detectSqlInjection(value: string): boolean {
  if (!value || typeof value !== "string") return false;

  const sqlPatterns = [
    /(\b(DROP|TRUNCATE|ALTER|EXEC|EXECUTE)\b)/i,
    /(--|#|\/\*)/,
    /(\bor\b.*=.*)/i,
    /(\band\b.*=.*)/i,
    /(;)/,
  ];

  return sqlPatterns.some((pattern) => pattern.test(value));
}

/**
 * NoSQL injection detection.
 * Detects common NoSQL injection patterns.
 */
export function detectNoSqlInjection(value: unknown): boolean {
  if (typeof value === "string") {
    const noSqlPatterns = [
      /\$where/,
      /\$ne/,
      /\$gt/,
      /\$lt/,
      /\$eq/,
      /\$regex/,
    ];
    return noSqlPatterns.some((pattern) => pattern.test(value));
  }

  if (typeof value === "object" && value !== null) {
    const keys = Object.keys(value);
    return keys.some((key) => key.startsWith("$"));
  }

  return false;
}

/**
 * Strict input validation for admin operations.
 */
export const AdminOperationSchema = z.object({
  idToken: IdTokenSchema,
});

export const BanUserSchema = AdminOperationSchema.extend({
  userId: FirebaseUidSchema,
  reason: z.string().min(5).max(500).trim(),
  duration: z.number().int().min(1).max(36500),
});

export const CreateLicenseSchema = AdminOperationSchema.extend({
  plan: z.enum(["Free", "Classic", "Pro"]),
  validityDays: z.number().int().min(1).max(3650),
});

export const BanIPSchema = AdminOperationSchema.extend({
  ipAddress: z
    .string()
    .ip({ version: "v4" })
    .or(z.string().ip({ version: "v6" })),
  reason: z.string().min(5).max(500).trim(),
  duration: z.number().int().min(1).max(36500),
});

export const ActivateLicenseSchema = z.object({
  idToken: IdTokenSchema,
  userId: FirebaseUidSchema,
  licenseKey: z.string().min(10).max(255),
});

export const DailyResetSchema = z.object({
  idToken: IdTokenSchema,
  userId: FirebaseUidSchema,
});

export const AIChatSchema = z.object({
  idToken: IdTokenSchema,
  userMessage: z.string().min(1).max(5000).trim(),
  conversationHistory: z
    .array(
      z.object({
        role: z.enum(["user", "assistant"]),
        content: z.string().max(5000),
      }),
    )
    .optional()
    .default([]),
  model: z
    .enum([
      "x-ai/grok-4.1-fast:free",
      "gpt-4",
      "gpt-3.5-turbo",
      "claude-3-opus",
      "claude-3-sonnet",
    ])
    .optional()
    .default("x-ai/grok-4.1-fast:free"),
  temperature: z.number().min(0).max(2).optional().default(0.7),
  maxTokens: z.number().int().min(1).max(4096).optional().default(2048),
});

export const AIConfigSchema = z.object({
  idToken: IdTokenSchema,
  model: z.string().optional(),
  temperature: z.number().min(0).max(2).optional(),
  maxTokens: z.number().int().min(1).max(4096).optional(),
});
