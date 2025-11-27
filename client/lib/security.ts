/**
 * Security utilities for input validation, sanitization, and output encoding.
 * Prevents XSS, injection attacks, and other security vulnerabilities.
 */
import DOMPurify from "dompurify";

/**
 * Escape HTML special characters to prevent XSS attacks.
 * Used when displaying user-generated content.
 */
export function escapeHtml(text: string): string {
  if (!text || typeof text !== "string") return "";
  // Use DOMPurify for safe HTML escaping
  return DOMPurify.sanitize(text, { ALLOWED_TAGS: [] });
}

/**
 * Sanitize user input by removing/escaping dangerous content.
 * Applied to all user inputs before storage.
 */
export function sanitizeInput(input: string): string {
  if (!input || typeof input !== "string") return "";

  // Trim whitespace
  let sanitized = input.trim();

  // Remove null bytes
  sanitized = sanitized.replace(/\0/g, "");

  // Remove control characters (except newlines and tabs)
  sanitized = sanitized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");

  // Use DOMPurify to remove all dangerous HTML tags and attributes
  // ALLOWED_TAGS: [] prevents any HTML tags from being kept
  sanitized = DOMPurify.sanitize(sanitized, {
    ALLOWED_TAGS: [],
    ALLOWED_ATTR: [],
  });

  return sanitized;
}

/**
 * Validate email format using regex.
 * Prevents obviously invalid emails from being processed.
 */
export function validateEmail(email: string): boolean {
  const emailRegex =
    /^[a-zA-Z0-9.!#$%&'*+\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
  return emailRegex.test(email);
}

/**
 * Validate message content.
 * - Min 1 character, max 5000
 * - No null bytes
 * - No excessively long lines
 */
export function validateMessageContent(content: string): boolean {
  if (!content || typeof content !== "string") return false;

  const length = content.trim().length;
  if (length < 1 || length > 5000) return false;

  // Check for null bytes
  if (content.includes("\0")) return false;

  // Check for excessively long lines (prevent buffer overflow)
  const lines = content.split("\n");
  if (lines.some((line) => line.length > 1000)) return false;

  return true;
}

/**
 * Validate conversation title.
 * - Min 1 character, max 255
 * - No special characters that could be injection vectors
 */
export function validateConversationTitle(title: string): boolean {
  if (!title || typeof title !== "string") return false;

  const length = title.trim().length;
  if (length < 1 || length > 255) return false;

  // Check for null bytes
  if (title.includes("\0")) return false;

  // Allow only safe characters
  const safeRegex = /^[a-zA-Z0-9\s\-_.àâäéèêëïîôöùûüçœæ]{1,255}$/;
  return safeRegex.test(title);
}

/**
 * Validate user ID format.
 * Firebase UID is typically 28 characters of alphanumeric.
 */
export function validateUserId(userId: string): boolean {
  if (!userId || typeof userId !== "string") return false;
  const uidRegex = /^[a-zA-Z0-9]{20,40}$/;
  return uidRegex.test(userId);
}

/**
 * Validate conversation ID (Firestore document ID).
 */
export function validateConversationId(conversationId: string): boolean {
  if (!conversationId || typeof conversationId !== "string") return false;
  // Firestore IDs are alphanumeric with some special chars
  const docIdRegex = /^[a-zA-Z0-9\-_]{1,255}$/;
  return docIdRegex.test(conversationId);
}

/**
 * Rate limit helper - check if action should be allowed.
 * Uses localStorage to track requests per time window.
 */
export class RateLimiter {
  private key: string;
  private maxRequests: number;
  private windowMs: number;

  constructor(key: string, maxRequests: number = 10, windowMs: number = 60000) {
    this.key = `ratelimit_${key}`;
    this.maxRequests = maxRequests;
    this.windowMs = windowMs;
  }

  isAllowed(): boolean {
    try {
      const data = localStorage.getItem(this.key);
      const now = Date.now();

      if (!data) {
        localStorage.setItem(
          this.key,
          JSON.stringify({ count: 1, resetAt: now + this.windowMs }),
        );
        return true;
      }

      const parsed = JSON.parse(data);

      if (now > parsed.resetAt) {
        localStorage.setItem(
          this.key,
          JSON.stringify({ count: 1, resetAt: now + this.windowMs }),
        );
        return true;
      }

      if (parsed.count >= this.maxRequests) {
        return false;
      }

      parsed.count++;
      localStorage.setItem(this.key, JSON.stringify(parsed));
      return true;
    } catch {
      return true;
    }
  }

  reset(): void {
    try {
      localStorage.removeItem(this.key);
    } catch {
      // Silently fail if localStorage is unavailable
    }
  }
}

/**
 * Detect and prevent common injection patterns.
 * Checks for SQL, NoSQL, XSS, and command injection attempts.
 */
export function detectInjectionAttempt(input: string): boolean {
  if (!input || typeof input !== "string") return false;

  const suspiciousPatterns = [
    // SQL injection patterns
    /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|WHERE|OR|AND)\b)/i,
    // NoSQL injection patterns
    /[\{\}\$\[\]]/,
    // Script injection
    /<script[^>]*>/i,
    /javascript:/i,
    // Command injection
    /[;&|`$()]/,
    // Path traversal
    /\.\.\//,
    /\.\.\\/, // Windows path traversal
  ];

  return suspiciousPatterns.some((pattern) => pattern.test(input));
}

/**
 * Create a secure message object for storage.
 * Validates and sanitizes all fields.
 */
export function createSecureMessage(
  conversationId: string,
  userId: string,
  content: string,
): {
  conversationId: string;
  userId: string;
  content: string;
  sanitizedContent: string;
} | null {
  // Validate IDs
  if (!validateConversationId(conversationId)) {
    console.error("Invalid conversation ID format");
    return null;
  }

  if (!validateUserId(userId)) {
    console.error("Invalid user ID format");
    return null;
  }

  // Validate and sanitize content
  if (!validateMessageContent(content)) {
    console.error("Invalid message content");
    return null;
  }

  // Detect injection attempts
  if (detectInjectionAttempt(content)) {
    console.error("Potential injection attack detected in message content");
    return null;
  }

  const sanitizedContent = sanitizeInput(content);

  return {
    conversationId,
    userId,
    content: sanitizedContent,
    sanitizedContent: sanitizedContent, // Same as content after sanitization
  };
}

/**
 * Validate and sanitize a conversation title.
 */
export function createSecureConversation(
  userId: string,
  title: string,
): {
  userId: string;
  title: string;
  sanitizedTitle: string;
} | null {
  // Validate ID
  if (!validateUserId(userId)) {
    console.error("Invalid user ID format");
    return null;
  }

  // Validate title
  if (!validateConversationTitle(title)) {
    console.error("Invalid conversation title");
    return null;
  }

  // Detect injection attempts
  if (detectInjectionAttempt(title)) {
    console.error("Potential injection attack detected in conversation title");
    return null;
  }

  const sanitizedTitle = sanitizeInput(title);

  return {
    userId,
    title: sanitizedTitle,
    sanitizedTitle: sanitizedTitle,
  };
}

/**
 * CSRF token helper (for future CSRF protection).
 */
export function generateCSRFToken(): string {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return Array.from(array, (byte) => byte.toString(16).padStart(2, "0")).join(
    "",
  );
}

/**
 * Store and verify CSRF token.
 */
export function storeCSRFToken(token: string): void {
  sessionStorage.setItem("csrf_token", token);
}

export function getCSRFToken(): string | null {
  return sessionStorage.getItem("csrf_token");
}

/**
 * Validate CSRF token from server response.
 */
export function validateCSRFToken(token: string): boolean {
  const stored = getCSRFToken();
  return stored !== null && stored === token;
}
