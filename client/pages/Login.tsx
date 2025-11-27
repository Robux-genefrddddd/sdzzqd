import { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { signInWithEmailAndPassword } from "firebase/auth";
import { auth } from "@/lib/firebase";
import { Mail, Lock } from "lucide-react";
import { toast } from "sonner";
import { IPService } from "@/lib/ip-service";

export default function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
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

      const userCredential = await signInWithEmailAndPassword(
        auth,
        email,
        password,
      );

      // Record or update user IP
      if (userCredential.user.uid) {
        await IPService.updateUserIPLogin(userCredential.user.uid, userIP);
      }

      toast.success("Connecté avec succès!");
      navigate("/");
    } catch (error) {
      let message = "Erreur de connexion";

      if (error && typeof error === "object") {
        const firebaseError = error as { code?: string; message?: string };

        // Map Firebase error codes to user-friendly messages
        const errorMap: Record<string, string> = {
          "auth/user-not-found":
            "Cet email n'existe pas. Créez d'abord un compte.",
          "auth/wrong-password": "Mot de passe incorrect",
          "auth/invalid-credential": "Email ou mot de passe incorrect",
          "auth/invalid-email": "Email invalide",
          "auth/user-disabled": "Ce compte a été désactivé",
          "auth/network-request-failed":
            "Erreur de connexion réseau. Vérifiez votre connexion internet.",
          "auth/too-many-requests":
            "Trop de tentatives de connexion. Veuillez réessayer plus tard.",
        };

        if (firebaseError.code) {
          message = errorMap[firebaseError.code] || firebaseError.code;
        } else if (firebaseError.message) {
          if (firebaseError.message.includes("USER_NOT_FOUND")) {
            message = "Cet email n'existe pas. Créez d'abord un compte.";
          } else if (
            firebaseError.message.includes("INVALID_PASSWORD") ||
            firebaseError.message.includes("INVALID_LOGIN_CREDENTIALS")
          ) {
            message = "Email ou mot de passe incorrect";
          } else if (firebaseError.message.includes("INVALID_EMAIL")) {
            message = "Email invalide";
          } else if (firebaseError.message.includes("USER_DISABLED")) {
            message = "Ce compte a été désactivé";
          } else {
            message = firebaseError.message;
          }
        }
      } else if (error instanceof Error) {
        message = error.message;
      }

      console.error("Login error:", error);
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
            Bienvenue
          </h1>

          {/* Tagline */}
          <p className="text-gray-400 text-sm leading-relaxed max-w-sm mx-auto">
            Ravi de vous revoir. Entrez pour accéder à votre assistant
            intelligent.
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
          <form onSubmit={handleLogin} className="space-y-5">
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
                  e.currentTarget.style.border =
                    "1px solid rgba(59, 130, 246, 0.5)";
                  e.currentTarget.style.boxShadow =
                    "0 0 12px rgba(59, 130, 246, 0.2)";
                }}
                onBlur={(e) => {
                  e.currentTarget.style.border =
                    "1px solid rgba(255, 255, 255, 0.07)";
                  e.currentTarget.style.boxShadow =
                    "0 0 0 0 rgba(59, 130, 246, 0)";
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
                  e.currentTarget.style.border =
                    "1px solid rgba(59, 130, 246, 0.5)";
                  e.currentTarget.style.boxShadow =
                    "0 0 12px rgba(59, 130, 246, 0.2)";
                }}
                onBlur={(e) => {
                  e.currentTarget.style.border =
                    "1px solid rgba(255, 255, 255, 0.07)";
                  e.currentTarget.style.boxShadow =
                    "0 0 0 0 rgba(59, 130, 246, 0)";
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

            {/* Login Button - SaaS Pro Style */}
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
                (e.currentTarget as HTMLButtonElement).style.transform =
                  "scale(1)";
              }}
            >
              {loading ? (
                <span className="flex items-center justify-center gap-2">
                  <span className="inline-block w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                  Connexion en cours...
                </span>
              ) : (
                "Se Connecter"
              )}
            </button>
          </form>

          {/* Divider */}
          <div className="my-6 flex items-center gap-3">
            <div className="flex-1 h-px bg-gradient-to-r from-transparent via-white/10 to-transparent" />
            <span className="text-xs text-gray-600">OU</span>
            <div className="flex-1 h-px bg-gradient-to-r from-transparent via-white/10 to-transparent" />
          </div>

          {/* Register Link */}
          <div className="text-center">
            <p className="text-sm text-gray-500 mb-3">Pas encore de compte?</p>
            <Link
              to="/register"
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
              Créer un compte
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
