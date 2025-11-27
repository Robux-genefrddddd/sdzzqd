import { useState } from "react";
import { toast } from "sonner";
import { useAuth } from "@/contexts/AuthContext";
import { doc, updateDoc } from "firebase/firestore";
import { db } from "@/lib/firebase";
import { Dialog, DialogContent, DialogTitle } from "@/components/ui/dialog";

interface LicenseActivationModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export function LicenseActivationModal({
  isOpen,
  onClose,
}: LicenseActivationModalProps) {
  const { user } = useAuth();
  const [licenseKey, setLicenseKey] = useState("");
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(false);

  const handleActivate = async () => {
    if (!licenseKey.trim()) {
      toast.error("Entrez une clé de licence");
      return;
    }

    if (!user?.uid) {
      toast.error("Vous devez être connecté");
      return;
    }

    setLoading(true);
    try {
      // Get idToken from Firebase Auth
      const idToken = await user.getIdToken();
      if (!idToken) {
        toast.error("Erreur d'authentification");
        setLoading(false);
        return;
      }

      // Call your license activation API
      const response = await fetch("/api/activate-license", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          licenseKey: licenseKey.trim(),
          userId: user.uid,
          idToken,
        }),
      });

      if (!response.ok) {
        try {
          const error = await response.json();
          toast.error(error.message || "Clé de licence invalide");
        } catch {
          toast.error("Clé de licence invalide");
        }
        return;
      }

      const data = await response.json();

      // Update local user data in Firestore to trigger auth context refresh
      await updateDoc(doc(db, "users", user.uid), {
        messagesUsed: 0,
        messagesLimit: data.messageLimit,
        plan: data.plan,
        licenseKey: licenseKey.trim(),
        licenseExpiresAt: data.expiresAt,
        lastMessageReset: Date.now(),
      });

      setSuccess(true);
      toast.success("Licence activée avec succès!");
      setTimeout(() => {
        onClose();
        setLicenseKey("");
        setSuccess(false);
      }, 2000);
    } catch (error) {
      console.error("Error activating license:", error);
      toast.error("Erreur lors de l'activation de la licence");
    } finally {
      setLoading(false);
    }
  };

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="border border-gray-800 rounded-lg p-0 bg-black shadow-xl">
        <DialogTitle className="sr-only">Activer une Licence</DialogTitle>
        {success ? (
          <div className="flex flex-col items-center justify-center py-12 px-8 space-y-6">
            <div className="text-center space-y-2">
              <p className="text-2xl font-bold text-white">Licence activée!</p>
              <p className="text-sm text-gray-400">
                Votre plan a été mis à jour avec succès.
              </p>
              <p className="text-xs text-gray-500 mt-2">
                Vous pouvez continuer à utiliser l'IA sans limites.
              </p>
            </div>
          </div>
        ) : (
          <div className="space-y-6 p-8">
            <div className="space-y-2">
              <h2 className="text-2xl font-bold text-white">
                Activer une Licence
              </h2>
              <p className="text-sm text-gray-400">
                Entrez votre clé de licence pour accéder à toutes les
                fonctionnalités
              </p>
            </div>

            <div className="space-y-3">
              <label className="block">
                <span className="text-sm font-semibold text-gray-300 mb-2 block">
                  Clé de licence
                </span>
                <input
                  type="text"
                  value={licenseKey}
                  onChange={(e) => setLicenseKey(e.target.value)}
                  placeholder="Entrez votre clé de licence..."
                  className="w-full bg-gray-900 border border-gray-700 rounded-lg px-4 py-3 text-white placeholder-gray-600 focus:outline-none focus:border-gray-500 focus:ring-1 focus:ring-gray-600 transition-all text-sm"
                  disabled={loading}
                  onKeyPress={(e) => {
                    if (e.key === "Enter") {
                      handleActivate();
                    }
                  }}
                />
              </label>
            </div>

            <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
              <p className="text-xs text-gray-400">
                Vous n'avez pas de clé? Contactez l'administrateur pour obtenir
                une licence.
              </p>
            </div>

            <div className="flex gap-3 pt-2">
              <button
                onClick={onClose}
                disabled={loading}
                className="flex-1 px-4 py-3 text-gray-300 border border-gray-700 rounded-lg hover:bg-gray-900 hover:border-gray-600 transition-all disabled:opacity-50 disabled:cursor-not-allowed font-medium text-sm"
              >
                Annuler
              </button>
              <button
                onClick={handleActivate}
                disabled={loading || !licenseKey.trim()}
                className="flex-1 px-4 py-3 bg-white text-black font-semibold rounded-lg hover:bg-gray-200 transition-all disabled:opacity-50 disabled:cursor-not-allowed text-sm"
              >
                {loading ? "Activation..." : "Activer"}
              </button>
            </div>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
