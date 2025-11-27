import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { useState, useEffect } from "react";
import { Moon, LogOut, Loader2, Sun } from "lucide-react";
import { useAuth } from "@/contexts/AuthContext";
import { ProfilePhotoUpload } from "@/components/ProfilePhotoUpload";
import { doc, updateDoc } from "firebase/firestore";
import { db } from "@/lib/firebase";
import { signOut } from "firebase/auth";
import { auth } from "@/lib/firebase";
import { useNavigate } from "react-router-dom";
import { toast } from "sonner";

interface SettingsModalProps {
  isOpen: boolean;
  onOpenChange: (open: boolean) => void;
}

export function SettingsModal({ isOpen, onOpenChange }: SettingsModalProps) {
  const { user, userData } = useAuth();
  const navigate = useNavigate();
  const [displayName, setDisplayName] = useState("");
  const [darkMode, setDarkMode] = useState(true);
  const [isSaving, setIsSaving] = useState(false);
  const [hasChanges, setHasChanges] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);

  useEffect(() => {
    if (userData?.displayName) {
      setDisplayName(userData.displayName);
    }
  }, [userData?.displayName, isOpen]);

  const handleDisplayNameChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value.slice(0, 10);
    setDisplayName(value);
    setHasChanges(true);
  };

  const handleDarkModeToggle = async () => {
    try {
      const newDarkMode = !darkMode;
      setDarkMode(newDarkMode);
      
      if (user?.uid) {
        const userRef = doc(db, "users", user.uid);
        await updateDoc(userRef, {
          darkMode: newDarkMode,
        });
        
        if (newDarkMode) {
          document.documentElement.classList.add("dark");
        } else {
          document.documentElement.classList.remove("dark");
        }
      }
      
      localStorage.setItem("darkMode", JSON.stringify(newDarkMode));
      toast.success(newDarkMode ? "Mode sombre activé" : "Mode clair activé");
    } catch (error) {
      console.error("Error toggling dark mode:", error);
      setDarkMode(!darkMode);
      toast.error("Erreur lors du changement de mode");
    }
  };

  const handleSaveChanges = async () => {
    if (!user?.uid || !displayName.trim()) {
      toast.error("Le pseudo ne peut pas être vide");
      return;
    }

    try {
      setIsSaving(true);
      const userRef = doc(db, "users", user.uid);
      await updateDoc(userRef, {
        displayName: displayName.trim(),
      });
      setHasChanges(false);
      setSaveSuccess(true);
      toast.success("Paramètres sauvegardés");
      
      setTimeout(() => setSaveSuccess(false), 2000);
    } catch (error) {
      console.error("Error saving settings:", error);
      toast.error("Erreur lors de la sauvegarde");
    } finally {
      setIsSaving(false);
    }
  };

  const handleLogout = async () => {
    try {
      await signOut(auth);
      navigate("/login");
      onOpenChange(false);
      toast.success("Déconnecté avec succès");
    } catch (error) {
      console.error("Error logging out:", error);
      toast.error("Erreur lors de la déconnexion");
    }
  };

  return (
    <Dialog open={isOpen} onOpenChange={onOpenChange}>
      <DialogContent className="bg-[#0f0f0f] border-0 rounded-[12px] w-[460px] max-h-[85vh] flex flex-col p-0 overflow-hidden shadow-2xl">
        {/* Header */}
        <DialogHeader className="px-6 py-4 border-b border-white/[0.06]">
          <DialogTitle className="text-foreground text-lg font-semibold">
            Paramètres
          </DialogTitle>
        </DialogHeader>

        {/* Scrollable Content */}
        <div className="flex-1 overflow-y-auto px-6 py-5">
          <div className="space-y-5">
            {/* Section 1: Profile Photo */}
            {user?.uid && (
              <div
                className="animate-fadeIn"
                style={{ animationDelay: "0.05s" }}
              >
                <div className="flex items-center gap-3 mb-4">
                  <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-primary/60 to-primary/80 flex items-center justify-center flex-shrink-0">
                    <span className="text-xs font-semibold text-primary-foreground">
                      {userData?.displayName?.[0]?.toUpperCase() || "U"}
                    </span>
                  </div>
                  <h3 className="text-sm font-semibold text-foreground">
                    Photo de profil
                  </h3>
                </div>
                <div className="bg-white/[0.02] border border-white/[0.08] rounded-[14px] p-5 shadow-sm">
                  <ProfilePhotoUpload
                    userId={user.uid}
                    currentPhotoUrl={
                      userData?.profilePhotoURL || user.photoURL || undefined
                    }
                    displayName={
                      userData?.displayName || user.displayName || "User"
                    }
                  />
                </div>
              </div>
            )}

            {/* Section 2: Display Name / Pseudo */}
            <div
              className="animate-fadeIn"
              style={{ animationDelay: "0.1s" }}
            >
              <div className="flex items-center gap-3 mb-4">
                <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-primary/60 to-primary/80 flex items-center justify-center flex-shrink-0">
                  <span className="text-xs font-semibold text-primary-foreground">
                    A
                  </span>
                </div>
                <h3 className="text-sm font-semibold text-foreground">
                  Pseudo
                </h3>
              </div>
              <div className="space-y-2.5">
                <input
                  type="text"
                  value={displayName}
                  onChange={handleDisplayNameChange}
                  placeholder="Votre pseudo..."
                  maxLength={10}
                  className="w-full bg-white/[0.02] border border-white/[0.08] rounded-[12px] px-4 py-3 text-foreground placeholder-foreground/40 focus:outline-none focus:border-primary/50 focus:bg-white/[0.05] transition-all duration-200 text-sm"
                />
                <div className="flex items-center justify-between">
                  <p className="text-xs text-foreground/60">
                    Modifiez votre nom d'utilisateur
                  </p>
                  <span className="text-xs text-foreground/50 font-medium">
                    {displayName.length}/10
                  </span>
                </div>
              </div>
            </div>

            {/* Section 3: Dark Mode */}
            <div
              className="animate-fadeIn"
              style={{ animationDelay: "0.15s" }}
            >
              <div className="flex items-center gap-3 mb-4">
                <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-primary/60 to-primary/80 flex items-center justify-center flex-shrink-0">
                  <Moon size={16} className="text-primary-foreground" />
                </div>
                <h3 className="text-sm font-semibold text-foreground">
                  Apparence
                </h3>
              </div>
              <div className="bg-white/[0.02] border border-white/[0.08] rounded-[14px] p-4 flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-foreground">
                    Mode sombre
                  </p>
                  <p className="text-xs text-foreground/50 mt-0.5">
                    Interface sombre premium
                  </p>
                </div>
                
                {/* iOS 17 Style Toggle */}
                <button
                  onClick={handleDarkModeToggle}
                  className={`relative w-12 h-7 rounded-full transition-all duration-300 flex items-center ${
                    darkMode
                      ? "bg-primary/40"
                      : "bg-white/[0.1]"
                  }`}
                >
                  <div
                    className={`absolute w-6 h-6 rounded-full bg-white shadow-md transition-all duration-300 flex items-center justify-center ${
                      darkMode ? "translate-x-5" : "translate-x-0.5"
                    }`}
                  >
                    {darkMode ? (
                      <Moon size={14} className="text-primary" />
                    ) : (
                      <Sun size={14} className="text-yellow-500" />
                    )}
                  </div>
                </button>
              </div>
            </div>

            {/* Section 4: Email Display */}
            <div
              className="animate-fadeIn"
              style={{ animationDelay: "0.2s" }}
            >
              <div className="flex items-center gap-3 mb-4">
                <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-primary/60 to-primary/80 flex items-center justify-center flex-shrink-0">
                  <span className="text-xs font-semibold text-primary-foreground">
                    @
                  </span>
                </div>
                <h3 className="text-sm font-semibold text-foreground">
                  Compte
                </h3>
              </div>
              <div className="bg-white/[0.02] border border-white/[0.08] rounded-[14px] p-4">
                <div>
                  <p className="text-xs text-foreground/60 mb-1.5">
                    Adresse e-mail
                  </p>
                  <p className="text-sm font-medium text-foreground truncate">
                    {user?.email || "..."}
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Sticky Footer with Buttons */}
        <div className="border-t border-white/[0.08] px-6 py-4 space-y-3 bg-card/50 backdrop-blur-sm">
          <button
            onClick={handleSaveChanges}
            disabled={!hasChanges || isSaving}
            className={`w-full px-4 py-3 font-medium text-sm rounded-[12px] transition-all duration-300 flex items-center justify-center gap-2 ${
              saveSuccess
                ? "bg-green-500/20 text-green-400 border border-green-500/30"
                : "bg-primary/20 hover:bg-primary/30 text-primary border border-primary/30 hover:border-primary/50 disabled:opacity-50 disabled:cursor-not-allowed"
            }`}
          >
            {isSaving ? (
              <>
                <Loader2 size={16} className="animate-spin" />
                <span>Enregistrement...</span>
              </>
            ) : saveSuccess ? (
              <>
                <span>✓</span>
                <span>Enregistré</span>
              </>
            ) : (
              "Enregistrer"
            )}
          </button>

          <button
            onClick={handleLogout}
            className="w-full px-4 py-3 bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/30 hover:border-red-500/50 font-medium text-sm rounded-[12px] transition-all duration-300 flex items-center justify-center gap-2 hover:shadow-sm"
          >
            <LogOut size={16} />
            <span>Se déconnecter</span>
          </button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
