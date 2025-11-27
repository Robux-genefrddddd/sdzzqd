import { RequestHandler } from "express";
import { z } from "zod";

/**
 * Schema for checking VPN
 */
const CheckVPNSchema = z.object({
  ipAddress: z
    .string()
    .ip({ version: "v4" })
    .or(z.string().ip({ version: "v6" })),
});

/**
 * Get the client's IP address.
 * Safe public endpoint - used to detect client IP for VPN and ban checking.
 */
export const handleGetIP: RequestHandler = (req, res) => {
  const ipAddress =
    (req.headers["x-forwarded-for"] as string)?.split(",")[0]?.trim() ||
    (req.headers["x-real-ip"] as string) ||
    req.socket.remoteAddress ||
    "0.0.0.0";

  // Validate IP format to prevent any injection
  try {
    z.string()
      .ip({ version: "v4" })
      .or(z.string().ip({ version: "v6" }))
      .parse(ipAddress);
  } catch {
    // If IP is invalid format, return a safe response
    return res.json({
      ip: "0.0.0.0",
    });
  }

  res.json({
    ip: ipAddress,
  });
};

/**
 * Check if an IP address is a VPN or data center.
 * Uses AbuseIPDB API for detection.
 */
export const handleCheckVPN: RequestHandler = async (req, res) => {
  try {
    // Validate input
    const validated = CheckVPNSchema.parse(req.body);
    const { ipAddress } = validated;

    // If no API key, return safe default
    if (!process.env.ABUSEIPDB_API_KEY) {
      console.warn("ABUSEIPDB_API_KEY not configured");
      return res.json({
        isVPN: false,
        provider: undefined,
      });
    }

    const response = await fetch("https://api.abuseipdb.com/api/v2/check", {
      method: "POST",
      headers: {
        Key: process.env.ABUSEIPDB_API_KEY,
        Accept: "application/json",
      },
      body: new URLSearchParams({
        ipAddress,
        maxAgeInDays: "90",
      }),
    });

    if (!response.ok) {
      console.warn("AbuseIPDB API request failed:", response.status);
      return res.json({ isVPN: false });
    }

    const data = (await response.json()) as {
      data?: {
        usageType?: string;
        totalReports?: number;
      };
    };

    const isVPN =
      data.data?.usageType === "Data Center" ||
      (data.data?.totalReports || 0) > 5;

    res.json({
      isVPN,
      provider: data.data?.usageType || undefined,
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({
        error: "Invalid IP address format",
        details: error.errors,
      });
    }

    console.error("Error checking VPN:", error);
    return res.status(500).json({
      error: "Failed to check VPN status",
    });
  }
};
