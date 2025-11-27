import { useState, useEffect } from "react";
import { useNavigate, Link } from "react-router-dom";
import { createUserWithEmailAndPassword } from "firebase/auth";
import { doc, setDoc, getDoc } from "firebase/firestore";
import { auth, db } from "@/lib/firebase";
import { PlanType, UserData } from "@/contexts/AuthContext";
import { Mail, Lock, Key } from "lucide-react";
import { toast } from "sonner";
import { IPService } from "@/lib/ip-service";

interface CaptchaData {
  num1: number;
  num2: number;
  operator: "+" | "-";
  answer: number;
}

export default function Register() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [licenseKey, setLicenseKey] = useState("");
  const [captcha, setCaptcha] = useState<CaptchaData | null>(null);
  const [captchaInput, setCaptchaInput] = useState("");
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  // Generate random math captcha on component mount
  useEffect(() => {
    generateCaptcha();
  }, []);

  const generateCaptcha = () => {
    const num1 = Math.floor(Math.random() * 50) + 1;
    const num2 = Math.floor(Math.random() * 50) + 1;
    const operator = Math.random() > 0.5 ? "+" : "-";
    const answer = operator === "+" ? num1 + num2 : num1 - num2;

    setCaptcha({ num1, num2, operator, answer });
    setCaptchaInput("");
  };

  const verifyCaptcha = (): boolean => {
    if (!captcha) return false;
    const userAnswer = parseInt(captchaInput, 10);
    return userAnswer === captcha.answer;
  };

  const validateLicenseKey = async (
    key: string,
  ): Promise<{ valid: boolean; plan?: PlanType }> => {
    if (!key.trim()) {
      return { valid: false };
    }

    try {
      const licenseDoc = await getDoc(doc(db, "licenses", key));

      if (!licenseDoc.exists()) {
        return { valid: false };
      }

      const licenseData = licenseDoc.data();

      if (!licenseData.active) {
        return { valid: false };
      }

      return { valid: true, plan: licenseData.plan as PlanType };
    } catch (error) {
      return { valid: false };
    }
  };

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();

    // Verify captcha
    if (!verifyCaptcha()) {
      toast.error("Réponse au captcha incorrecte. Veuillez réessayer.");
      generateCaptcha();
      return;
    }

    setLoading(true);

    try {
      // Get user's IP address
      const userIP = await IPService.getUserIP();

      // Check IP ban
      const ipBan = await IPService.checkIPBan(userIP);
      if (ipBan) {
        toast.error(
          "Votre adresse IP est bannie: " +
            ipBan.reason +
            (ipBan.expiresAt
              ? " (Expire le " +
                ipBan.expiresAt.toDate().toLocaleDateString() +
                ")"
              : " (Permanent)"),
        );
        setLoading(false);
        return;
      }

      // Check account limit per IP (max 1 account)
      const ipCheck = await IPService.checkIPLimit(userIP, 1);
      if (ipCheck.isLimitExceeded) {
        toast.error(
          "Vous avez atteint le nombre maximal de comptes autorisés depuis votre adresse IP",
        );
        setLoading(false);
        return;
      }

      let planToUse: PlanType = "Free";

      if (licenseKey.trim()) {
        const licenseValidation = await validateLicenseKey(licenseKey);

        if (!licenseValidation.valid) {
          toast.error("Clé de licence invalide ou inactive");
          setLoading(false);
          return;
        }

        if (licenseValidation.plan) {
          planToUse = licenseValidation.plan;
        }
      }

      const userCredential = await createUserWithEmailAndPassword(
        auth,
        email,
        password,
      );
      const user = userCredential.user;

      const planLimits: Record<PlanType, number> = {
        Free: 10,
        Classic: 50,
        Pro: 999,
      };

      const userData: UserData = {
        uid: user.uid,
        email: user.email || "",
        displayName: email.split("@")[0],
        plan: planToUse,
        role: "user",
        category: "individual",
        messagesUsed: 0,
        messagesLimit: planLimits[planToUse],
        createdAt: Date.now(),
        isAdmin: false,
      };

      // Only add licenseKey if it was provided
      if (licenseKey.trim()) {
        (userData as any).licenseKey = licenseKey.trim();
      }

      // Create user document in Firestore
      try {
        await setDoc(doc(db, "users", user.uid), userData);
      } catch (firestoreError) {
        console.error("Firestore error:", firestoreError);
        throw new Error(
          "Impossible de créer le profil utilisateur. Veuillez réessayer.",
        );
      }

      // Record user IP (non-critical, don't block registration)
      try {
        await IPService.recordUserIP(user.uid, user.email || "", userIP);
      } catch (ipError) {
        console.error("IP recording error (non-critical):", ipError);
      }

      toast.success("Compte créé avec succès!");
      navigate("/");
    } catch (error) {
      let message = "Erreur d'inscription";

      if (error && typeof error === "object") {
        const firebaseError = error as { code?: string; message?: string };

        // Map Firebase error codes to user-friendly messages
        const errorMap: Record<string, string> = {
          "auth/email-already-in-use": "Cet email est déjà utilisé",
          "auth/invalid-email": "Email invalide",
          "auth/weak-password":
            "Le mot de passe doit contenir au moins 6 caractères",
          "auth/operation-not-allowed": "L'inscription n'est pas autorisée",
          "auth/network-request-failed":
            "Erreur de connexion réseau. Vérifiez votre connexion internet.",
        };

        if (firebaseError.code) {
          message = errorMap[firebaseError.code] || firebaseError.code;
        } else if (firebaseError.message) {
          // Handle cases where Firebase returns a message instead of code
          if (firebaseError.message.includes("EMAIL_EXISTS")) {
            message = "Cet email est déjà utilisé";
          } else if (firebaseError.message.includes("WEAK_PASSWORD")) {
            message = "Le mot de passe doit contenir au moins 6 caractères";
          } else if (firebaseError.message.includes("INVALID_EMAIL")) {
            message = "Email invalide";
          } else {
            message = firebaseError.message;
          }
        }
      } else if (error instanceof Error) {
        message = error.message;
      }

      toast.error(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-4 relative overflow-hidden bg-[#0a0a0a]">
      {/* Premium Background with Gradient + Blur + Noise */}
      <div className="absolute inset-0 z-0">
        {/* Radial gradient spotlight effect */}
        <div
          className="absolute inset-0"
          style={{
            background:
              "radial-gradient(circle at 50% 20%, rgba(255,255,255,0.06), transparent 50%)",
          }}
        />

        {/* Subtle noise texture */}
        <div
          className="absolute inset-0 opacity-[0.015]"
          style={{
            backgroundImage:
              "url('data:image/svg+xml,%3Csvg width=%27100%27 height=%27100%27 xmlns=%27http://www.w3.org/2000/svg%27%3E%3Cfilter id=%27noise%27%3E%3CfeTurbulence type=%27fractalNoise%27 baseFrequency=%270.9%27 numOctaves=%274%27 seed=%272%27 /%3E%3C/filter%3E%3Crect width=%27100%27 height=%27100%27 filter=%27url(%23noise)%27 opacity=%271%27/%3E%3C/svg%3E')",
          }}
        />

        {/* Animated gradient blobs */}
        <div className="absolute top-0 right-0 w-96 h-96 bg-gradient-to-br from-blue-500/10 to-transparent rounded-full blur-3xl opacity-40" />
        <div className="absolute bottom-0 left-0 w-96 h-96 bg-gradient-to-tr from-purple-500/10 to-transparent rounded-full blur-3xl opacity-40" />
      </div>

      {/* Main Content Container */}
      <div className="relative z-10 w-full max-w-[460px]">
        {/* Header Section with Title */}
        <div className="text-center mb-8 animate-fadeIn">
          {/* Main Title */}
          <h1
            className="text-[28px] font-semibold text-white mb-3"
            style={{ letterSpacing: "-0.5px" }}
          >
            Créez votre compte
          </h1>

          {/* Tagline */}
          <p className="text-gray-400 text-sm leading-relaxed max-w-sm mx-auto">
            Rejoignez VanIA et explorez l'intelligence artificielle de nouvelle
            génération.
          </p>
        </div>

        {/* Premium Card Container */}
        <div
          className="rounded-2xl p-10 animate-slideUp"
          style={{
            background: "rgba(17, 17, 17, 0.6)",
            backdropFilter: "blur(14px)",
            border: "1px solid rgba(255, 255, 255, 0.08)",
            boxShadow: "0 8px 32px rgba(0, 0, 0, 0.4)",
          }}
        >
          {/* Form */}
          <form onSubmit={handleRegister} className="space-y-5">
            {/* Email Field */}
            <div className="group">
              <label className="block text-xs font-medium text-gray-300 mb-2 uppercase tracking-wider">
                Email
              </label>
              <div
                className="relative rounded-2xl transition-all duration-200 flex items-center"
                style={{
                  background: "rgba(255, 255, 255, 0.03)",
                  border: "1px solid rgba(255, 255, 255, 0.07)",
                  boxShadow: "0 0 0 0 rgba(59, 130, 246, 0)",
                }}
                onFocus={(e) => {
                  e.currentTarget.style.border = "1px solid rgba(59, 130, 246, 0.5)";
                  e.currentTarget.style.boxShadow =
                    "0 0 12px rgba(59, 130, 246, 0.2)";
                }}
                onBlur={(e) => {
                  e.currentTarget.style.border = "1px solid rgba(255, 255, 255, 0.07)";
                  e.currentTarget.style.boxShadow = "0 0 0 0 rgba(59, 130, 246, 0)";
                }}
              >
                <Mail
                  size={18}
                  className="absolute left-4 text-gray-500 pointer-events-none"
                />
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="votre@email.com"
                  className="w-full bg-transparent pl-12 pr-4 py-3.5 text-white placeholder-gray-600 focus:outline-none text-sm font-medium"
                  required
                />
              </div>
            </div>

            {/* Password Field */}
            <div className="group">
              <label className="block text-xs font-medium text-gray-300 mb-2 uppercase tracking-wider">
                Mot de passe
              </label>
              <div
                className="relative rounded-2xl transition-all duration-200 flex items-center"
                style={{
                  background: "rgba(255, 255, 255, 0.03)",
                  border: "1px solid rgba(255, 255, 255, 0.07)",
                  boxShadow: "0 0 0 0 rgba(59, 130, 246, 0)",
                }}
                onFocus={(e) => {
                  e.currentTarget.style.border = "1px solid rgba(59, 130, 246, 0.5)";
                  e.currentTarget.style.boxShadow =
                    "0 0 12px rgba(59, 130, 246, 0.2)";
                }}
                onBlur={(e) => {
                  e.currentTarget.style.border = "1px solid rgba(255, 255, 255, 0.07)";
                  e.currentTarget.style.boxShadow = "0 0 0 0 rgba(59, 130, 246, 0)";
                }}
              >
                <Lock
                  size={18}
                  className="absolute left-4 text-gray-500 pointer-events-none"
                />
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  className="w-full bg-transparent pl-12 pr-4 py-3.5 text-white placeholder-gray-600 focus:outline-none text-sm font-medium"
                  required
                />
              </div>
            </div>

            {/* Math Captcha Field */}
            {captcha && (
              <div className="group">
                <label className="block text-xs font-medium text-gray-300 mb-2 uppercase tracking-wider">
                  Captcha: {captcha.num1} {captcha.operator} {captcha.num2} = ?
                </label>
                <input
                  type="number"
                  value={captchaInput}
                  onChange={(e) => setCaptchaInput(e.target.value)}
                  placeholder="Votre réponse"
                  className="w-full bg-transparent px-4 py-3.5 text-white placeholder-gray-600 focus:outline-none text-sm font-medium rounded-2xl"
                  style={{
                    background: "rgba(255, 255, 255, 0.03)",
                    border: "1px solid rgba(255, 255, 255, 0.07)",
                  }}
                  required
                />
                <p className="text-xs text-gray-600 mt-1">
                  Résolvez ce calcul simple pour vérifier que vous êtes humain.
                </p>
              </div>
            )}

            {/* License Key Field - Optional */}
            <div className="group">
              <label className="block text-xs font-medium text-gray-300 mb-2 uppercase tracking-wider">
                Clé de licence{" "}
                <span className="text-gray-600">(optionnel)</span>
              </label>
              <div
                className="relative rounded-2xl transition-all duration-200 flex items-center"
                style={{
                  background: "rgba(255, 255, 255, 0.03)",
                  border: "1px solid rgba(255, 255, 255, 0.07)",
                  boxShadow: "0 0 0 0 rgba(59, 130, 246, 0)",
                }}
                onFocus={(e) => {
                  e.currentTarget.style.border = "1px solid rgba(59, 130, 246, 0.5)";
                  e.currentTarget.style.boxShadow =
                    "0 0 12px rgba(59, 130, 246, 0.2)";
                }}
                onBlur={(e) => {
                  e.currentTarget.style.border = "1px solid rgba(255, 255, 255, 0.07)";
                  e.currentTarget.style.boxShadow = "0 0 0 0 rgba(59, 130, 246, 0)";
                }}
              >
                <Key
                  size={18}
                  className="absolute left-4 text-gray-500 pointer-events-none"
                />
                <input
                  type="text"
                  value={licenseKey}
                  onChange={(e) => setLicenseKey(e.target.value)}
                  placeholder="Entrez votre clé de licence"
                  className="w-full bg-transparent pl-12 pr-4 py-3.5 text-white placeholder-gray-600 focus:outline-none text-sm font-medium"
                />
              </div>
              <p className="text-xs text-gray-600 mt-2">
                Si vous n'avez pas de clé, un compte gratuit sera créé
              </p>
            </div>

            {/* Register Button - SaaS Pro Style */}
            <button
              type="submit"
              disabled={loading}
              className="w-full mt-8 rounded-2xl py-3.5 font-semibold text-white text-sm relative overflow-hidden group transition-all duration-200"
              style={{
                background: loading
                  ? "rgba(59, 130, 246, 0.5)"
                  : "linear-gradient(135deg, #1f2937 0%, #111827 100%)",
                boxShadow: loading
                  ? "0 4px 12px rgba(59, 130, 246, 0.2)"
                  : "0 8px 16px rgba(0, 0, 0, 0.3)",
              }}
              onMouseEnter={(e) => {
                if (!loading) {
                  (e.currentTarget as HTMLButtonElement).style.transform =
                    "scale(0.98)";
                }
              }}
              onMouseLeave={(e) => {
                (e.currentTarget as HTMLButtonElement).style.transform = "scale(1)";
              }}
            >
              {loading ? (
                <span className="flex items-center justify-center gap-2">
                  <span className="inline-block w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                  Inscription en cours...
                </span>
              ) : (
                "Créer un compte"
              )}
            </button>
          </form>

          {/* Divider */}
          <div className="my-6 flex items-center gap-3">
            <div className="flex-1 h-px bg-gradient-to-r from-transparent via-white/10 to-transparent" />
            <span className="text-xs text-gray-600">OU</span>
            <div className="flex-1 h-px bg-gradient-to-r from-transparent via-white/10 to-transparent" />
          </div>

          {/* Login Link */}
          <div className="text-center">
            <p className="text-sm text-gray-500 mb-3">
              Vous avez déjà un compte?
            </p>
            <Link
              to="/login"
              className="inline-block px-6 py-2.5 rounded-2xl text-white text-sm font-medium transition-all duration-200"
              style={{
                background: "rgba(255, 255, 255, 0.08)",
                border: "1px solid rgba(255, 255, 255, 0.12)",
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.background = "rgba(255, 255, 255, 0.12)";
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.background = "rgba(255, 255, 255, 0.08)";
              }}
            >
              Se Connecter
            </Link>
          </div>
        </div>

        {/* Footer */}
        <div className="text-center mt-8 text-xs text-gray-600 animate-fadeIn">
          © VanIA — Tous droits réservés
        </div>
      </div>
    </div>
  );
}
