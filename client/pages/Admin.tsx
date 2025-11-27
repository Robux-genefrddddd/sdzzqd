import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { signOut } from "firebase/auth";
import {
  collection,
  getDocs,
  doc,
  updateDoc,
  query,
  where,
} from "firebase/firestore";
import { auth, db } from "@/lib/firebase";
import { useAuth } from "@/contexts/AuthContext";
import {
  Users,
  Settings,
  LogOut,
  Edit2,
  Save,
  X,
  Key,
  Copy,
  Trash2,
  Brain,
  Shield,
  AlertCircle,
  Clock,
  BarChart3,
  Plus,
  ChevronRight,
  Home,
} from "lucide-react";
import { toast } from "sonner";
import { UserData, PlanType } from "@/contexts/AuthContext";
import { getAllLicenses, deactivateLicense, LicenseKey } from "@/lib/licenses";
import { AIService, AIConfig } from "@/lib/ai";
import {
  SystemNoticesService,
  UserBan,
  MaintenanceNotice,
} from "@/lib/system-notices";
import AdminUsersList from "@/components/AdminUsersList";
import AdminBanManagement from "@/components/AdminBanManagement";
import { GenerateLicenseModal } from "@/components/GenerateLicenseModal";

export default function Admin() {
  const { userData } = useAuth();
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState<
    "users" | "licenses" | "ai" | "system"
  >("users");
  const [users, setUsers] = useState<UserData[]>([]);
  const [licenses, setLicenses] = useState<LicenseKey[]>([]);
  const [aiConfig, setAiConfig] = useState<AIConfig | null>(null);
  const [bans, setBans] = useState<UserBan[]>([]);
  const [maintenanceNotices, setMaintenanceNotices] = useState<
    MaintenanceNotice[]
  >([]);
  const [loading, setLoading] = useState(true);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editData, setEditData] = useState<Partial<UserData>>({});
  const [showGenerateLicenseModal, setShowGenerateLicenseModal] =
    useState(false);
  const [savingAiConfig, setSavingAiConfig] = useState(false);
  const [userEmailToBan, setUserEmailToBan] = useState("");
  const [banReason, setBanReason] = useState("");
  const [banDuration, setBanDuration] = useState<number | null>(null);
  const [maintenanceTitle, setMaintenanceTitle] = useState("");
  const [maintenanceMessage, setMaintenanceMessage] = useState("");
  const [maintenanceDuration, setMaintenanceDuration] = useState(30);
  const [maintenanceSeverity, setMaintenanceSeverity] = useState<
    "info" | "warning" | "critical"
  >("warning");
  const [savingBan, setSavingBan] = useState(false);
  const [savingMaintenance, setSavingMaintenance] = useState(false);
  const [actionType, setActionType] = useState<"ban" | "warn">("ban");

  const planLimits: Record<PlanType, number> = {
    Free: 10,
    Classic: 500,
    Pro: 1000,
  };

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      await Promise.all([
        loadUsers(),
        loadLicenses(),
        loadAiConfig(),
        loadBans(),
        loadMaintenance(),
      ]);
    } catch (error) {
      toast.error("Erreur lors du chargement des données");
    } finally {
      setLoading(false);
    }
  };

  const loadAiConfig = async () => {
    try {
      const config = await AIService.getConfig();
      setAiConfig(config);
    } catch (error) {
      console.error("Erreur lors du chargement de la config IA", error);
    }
  };

  const loadBans = async () => {
    try {
      const allBans = await SystemNoticesService.getAllBans();
      setBans(allBans);
    } catch (error) {
      console.error("Erreur lors du chargement des bans", error);
    }
  };

  const loadMaintenance = async () => {
    try {
      const notices = await SystemNoticesService.getAllMaintenanceNotices();
      setMaintenanceNotices(notices);
    } catch (error) {
      console.error("Erreur lors du chargement de la maintenance", error);
    }
  };

  const loadUsers = async () => {
    try {
      const usersRef = collection(db, "users");
      const snapshot = await getDocs(usersRef);
      const usersList = snapshot.docs.map(
        (doc) =>
          ({
            ...doc.data(),
            uid: doc.id,
          }) as UserData,
      );
      setUsers(usersList);
    } catch (error) {
      toast.error("Erreur lors du chargement des utilisateurs");
    }
  };

  const loadLicenses = async () => {
    if (!userData?.uid) return;
    try {
      const allLicenses = await getAllLicenses(userData.uid);
      setLicenses(allLicenses);
    } catch (error) {
      toast.error("Erreur lors du chargement des clés de licence");
    }
  };

  const handleEditUser = (user: UserData) => {
    setEditingId(user.uid);
    setEditData(user);
  };

  const handleSaveUser = async () => {
    if (!editingId) return;

    try {
      const userRef = doc(db, "users", editingId);
      await updateDoc(userRef, editData);

      setUsers(
        users.map((u) => (u.uid === editingId ? { ...u, ...editData } : u)),
      );

      setEditingId(null);
      toast.success("Utilisateur mis à jour");
    } catch (error) {
      toast.error("Erreur lors de la mise à jour");
    }
  };

  const handleLicenseGenerated = async () => {
    await loadLicenses();
  };

  const handleCopyLicense = (key: string) => {
    navigator.clipboard.writeText(key);
    toast.success("Clé copiée");
  };

  const handleDeactivateLicense = async (key: string) => {
    try {
      await deactivateLicense(key);
      await loadLicenses();
      toast.success("Clé désactivée");
    } catch (error) {
      toast.error("Erreur lors de la désactivation");
    }
  };

  const handleSaveAiConfig = async () => {
    if (!aiConfig) return;

    setSavingAiConfig(true);
    try {
      await AIService.updateConfig(aiConfig);
      toast.success("Configuration IA mise à jour");
    } catch (error) {
      toast.error(
        error instanceof Error ? error.message : "Erreur lors de la sauvegarde",
      );
    } finally {
      setSavingAiConfig(false);
    }
  };

  const handleBanUser = async () => {
    if (!userEmailToBan || !banReason) {
      toast.error("Entrez un email et une raison");
      return;
    }

    setSavingBan(true);
    try {
      const user = users.find((u) => u.email === userEmailToBan);
      if (!user) {
        toast.error("Utilisateur non trouvé");
        return;
      }

      await SystemNoticesService.banUser(
        user.uid,
        user.email,
        banReason,
        banDuration || undefined,
      );

      toast.success("Utilisateur banni avec succès");
      setUserEmailToBan("");
      setBanReason("");
      setBanDuration(null);
      await loadBans();
    } catch (error) {
      toast.error("Erreur lors du ban");
    } finally {
      setSavingBan(false);
    }
  };

  const handleUnbanUser = async (userId: string) => {
    try {
      await SystemNoticesService.unbanUser(userId);
      toast.success("Utilisateur débanni");
      await loadBans();
    } catch (error) {
      toast.error("Erreur lors du déban");
    }
  };

  const handleCreateMaintenance = async () => {
    if (!maintenanceTitle || !maintenanceMessage) {
      toast.error("Entrez un titre et un message");
      return;
    }

    setSavingMaintenance(true);
    try {
      await SystemNoticesService.createMaintenanceNotice(
        maintenanceTitle,
        maintenanceMessage,
        maintenanceDuration,
        maintenanceSeverity,
      );

      toast.success("Maintenance créée");
      setMaintenanceTitle("");
      setMaintenanceMessage("");
      setMaintenanceDuration(30);
      setMaintenanceSeverity("warning");
      await loadMaintenance();
    } catch (error) {
      toast.error("Erreur lors de la création");
    } finally {
      setSavingMaintenance(false);
    }
  };

  const handleEndMaintenance = async (noticeId: string) => {
    try {
      await SystemNoticesService.endMaintenance(noticeId);
      toast.success("Maintenance terminée");
      await loadMaintenance();
    } catch (error) {
      toast.error("Erreur lors de la terminaison");
    }
  };

  const handleLogout = async () => {
    try {
      await signOut(auth);
      navigate("/login");
    } catch (error) {
      toast.error("Erreur lors de la déconnexion");
    }
  };

  if (!userData?.isAdmin) {
    return (
      <div className="min-h-screen bg-[#0a0a0a] flex items-center justify-center p-4 relative overflow-hidden">
        <div className="absolute inset-0">
          <div
            className="absolute inset-0"
            style={{
              background:
                "radial-gradient(circle at 50% 50%, rgba(255,255,255,0.03), transparent 50%)",
            }}
          />
          <div className="absolute top-0 right-0 w-96 h-96 bg-gradient-to-br from-blue-500/5 to-transparent rounded-full blur-3xl" />
          <div className="absolute bottom-0 left-0 w-96 h-96 bg-gradient-to-tr from-purple-500/5 to-transparent rounded-full blur-3xl" />
        </div>

        <div className="relative z-10 text-center">
          <AlertCircle size={48} className="mx-auto text-red-500 mb-4" />
          <h1 className="text-2xl font-bold text-white mb-2">Accès refusé</h1>
          <p className="text-gray-400 mb-6">Vous n'avez pas les permissions administrateur</p>
          <button
            onClick={() => navigate("/")}
            className="flex items-center gap-2 mx-auto px-6 py-3 rounded-2xl font-semibold text-white"
            style={{
              background: "linear-gradient(135deg, #3b82f6 0%, #2563eb 100%)",
              boxShadow: "0 8px 16px rgba(59, 130, 246, 0.3)",
            }}
          >
            <Home size={18} />
            Retour à l'accueil
          </button>
        </div>
      </div>
    );
  }

  const tabs = [
    { id: "users", label: "Utilisateurs", icon: Users },
    { id: "licenses", label: "Licences", icon: Key },
    { id: "ai", label: "Configuration IA", icon: Brain },
    { id: "system", label: "Système", icon: Shield },
  ];

  return (
    <div className="min-h-screen bg-[#0a0a0a]">
      {/* Background Effects */}
      <div className="fixed inset-0 z-0 pointer-events-none">
        <div
          className="absolute inset-0"
          style={{
            background:
              "radial-gradient(circle at 50% 20%, rgba(255,255,255,0.04), transparent 50%)",
          }}
        />
        <div className="absolute top-0 right-0 w-96 h-96 bg-gradient-to-br from-blue-500/8 to-transparent rounded-full blur-3xl opacity-40" />
        <div className="absolute bottom-0 left-0 w-96 h-96 bg-gradient-to-tr from-purple-500/8 to-transparent rounded-full blur-3xl opacity-40" />
      </div>

      {/* Header */}
      <div className="relative z-10 border-b border-white/10 backdrop-blur">
        <div className="max-w-7xl mx-auto px-6 py-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <button
                onClick={() => navigate("/")}
                className="p-2 hover:bg-white/10 rounded-lg transition-colors"
              >
                <Home size={20} className="text-gray-400 hover:text-white" />
              </button>
              <div className="w-12 h-12 rounded-2xl flex items-center justify-center"
                style={{
                  background: "linear-gradient(135deg, rgba(59, 130, 246, 0.2), rgba(147, 51, 234, 0.2))",
                  border: "1px solid rgba(255, 255, 255, 0.1)",
                }}
              >
                <Shield size={24} className="text-blue-400" />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-white">Panneau Admin</h1>
                <p className="text-xs text-gray-500">Gestion complète de la plateforme</p>
              </div>
            </div>

            <button
              onClick={handleLogout}
              className="flex items-center gap-2 px-4 py-2.5 rounded-2xl font-medium text-sm transition-all duration-200"
              style={{
                background: "rgba(255, 255, 255, 0.08)",
                border: "1px solid rgba(255, 255, 255, 0.12)",
                color: "rgb(209, 213, 219)",
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.background = "rgba(255, 255, 255, 0.12)";
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.background = "rgba(255, 255, 255, 0.08)";
              }}
            >
              <LogOut size={16} />
              Déconnexion
            </button>
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="relative z-10 border-b border-white/10 backdrop-blur">
        <div className="max-w-7xl mx-auto px-6">
          <div className="flex gap-1">
            {tabs.map((tab) => {
              const Icon = tab.icon;
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as any)}
                  className={`flex items-center gap-2 px-4 py-4 font-medium text-sm transition-all duration-200 border-b-2 ${
                    isActive
                      ? "border-blue-500 text-white"
                      : "border-transparent text-gray-400 hover:text-white"
                  }`}
                >
                  <Icon size={18} />
                  {tab.label}
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* Content */}
      <div className="relative z-10 max-w-7xl mx-auto px-6 py-8">
        {activeTab === "users" && (
          <div className="space-y-6">
            <div>
              <h2 className="text-xl font-bold text-white mb-2">Gestion des utilisateurs</h2>
              <p className="text-gray-400 text-sm">Gérez les comptes utilisateurs et les permissions</p>
            </div>
            <AdminUsersList
              onBanUser={(email) => {
                setUserEmailToBan(email);
                setActiveTab("system");
              }}
              onWarnUser={(email) => {
                setUserEmailToBan(email);
                setActionType("warn");
                setActiveTab("system");
              }}
            />
          </div>
        )}

        {activeTab === "licenses" && (
          <div className="space-y-6">
            {/* Header */}
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-xl font-bold text-white mb-2">Clés de licence</h2>
                <p className="text-gray-400 text-sm">Générez et gérez les clés d'accès premium</p>
              </div>
              <button
                onClick={() => setShowGenerateLicenseModal(true)}
                className="flex items-center gap-2 px-6 py-3 rounded-2xl font-semibold text-sm transition-all duration-200"
                style={{
                  background: "linear-gradient(135deg, #3b82f6 0%, #2563eb 100%)",
                  color: "white",
                  boxShadow: "0 8px 16px rgba(59, 130, 246, 0.3)",
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.transform = "translateY(-2px)";
                  e.currentTarget.style.boxShadow = "0 12px 20px rgba(59, 130, 246, 0.4)";
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.transform = "translateY(0)";
                  e.currentTarget.style.boxShadow = "0 8px 16px rgba(59, 130, 246, 0.3)";
                }}
              >
                <Plus size={18} />
                Nouvelle clé
              </button>
            </div>

            {/* Licenses Table */}
            <div
              className="rounded-2xl overflow-hidden"
              style={{
                background: "rgba(17, 17, 17, 0.6)",
                border: "1px solid rgba(255, 255, 255, 0.08)",
                boxShadow: "0 8px 32px rgba(0, 0, 0, 0.4)",
              }}
            >
              <div className="p-6 border-b border-white/10">
                <h3 className="font-semibold text-white flex items-center gap-2">
                  <Key size={18} />
                  Total: {licenses.length} clé(s)
                </h3>
              </div>

              {loading ? (
                <div className="p-12 text-center">
                  <p className="text-gray-500">Chargement des clés...</p>
                </div>
              ) : licenses.length === 0 ? (
                <div className="p-12 text-center">
                  <Key size={32} className="mx-auto text-gray-600 mb-3" />
                  <p className="text-gray-500">Aucune clé générée</p>
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead className="border-b border-white/10 bg-white/[0.02]">
                      <tr>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-400">
                          Clé
                        </th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-400">
                          Plan
                        </th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-400">
                          Statut
                        </th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-400">
                          Expire le
                        </th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-400">
                          Utilisée par
                        </th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-400">
                          Actions
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {licenses
                        .filter((license) => license && license.key)
                        .map((license) => (
                          <tr
                            key={`license-${license.key}`}
                            className="border-b border-white/10 hover:bg-white/5 transition-colors"
                          >
                            <td className="px-6 py-4">
                              <code className="text-white/70 text-sm font-mono bg-white/5 px-3 py-1.5 rounded-lg">
                                {license.key.substring(0, 20)}...
                              </code>
                            </td>
                            <td className="px-6 py-4">
                              <span className="text-gray-300 text-sm">{license.plan}</span>
                            </td>
                            <td className="px-6 py-4">
                              <span
                                className={`px-3 py-1 rounded-lg text-xs font-semibold ${
                                  license.active
                                    ? "bg-green-500/20 text-green-400"
                                    : "bg-red-500/20 text-red-400"
                                }`}
                              >
                                {license.active ? "Active" : "Inactive"}
                              </span>
                            </td>
                            <td className="px-6 py-4 text-gray-400 text-sm">
                              {license.expiresAt && !isNaN(license.expiresAt)
                                ? new Date(license.expiresAt).toLocaleDateString()
                                : "-"}
                            </td>
                            <td className="px-6 py-4 text-gray-400 text-sm">
                              {license.usedBy &&
                              typeof license.usedBy === "string"
                                ? `${license.usedBy.substring(0, 8)}...`
                                : "-"}
                            </td>
                            <td className="px-6 py-4">
                              <div className="flex gap-2">
                                <button
                                  onClick={() => handleCopyLicense(license.key)}
                                  className="p-2 rounded-lg hover:bg-white/10 text-gray-400 hover:text-white transition-colors"
                                  title="Copier"
                                >
                                  <Copy size={16} />
                                </button>
                                {license.active && (
                                  <button
                                    onClick={() =>
                                      handleDeactivateLicense(license.key)
                                    }
                                    className="p-2 rounded-lg hover:bg-red-500/20 text-gray-400 hover:text-red-400 transition-colors"
                                    title="Désactiver"
                                  >
                                    <Trash2 size={16} />
                                  </button>
                                )}
                              </div>
                            </td>
                          </tr>
                        ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === "ai" && (
          <div className="space-y-6">
            {/* Header */}
            <div>
              <h2 className="text-xl font-bold text-white mb-2">Configuration IA</h2>
              <p className="text-gray-400 text-sm">Paramétrez le modèle et le comportement de l'IA</p>
            </div>

            {/* AI Config Cards */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Model Parameters */}
              <div
                className="rounded-2xl p-6"
                style={{
                  background: "rgba(17, 17, 17, 0.6)",
                  border: "1px solid rgba(255, 255, 255, 0.08)",
                  boxShadow: "0 8px 32px rgba(0, 0, 0, 0.4)",
                }}
              >
                <h3 className="text-lg font-semibold text-white mb-6 flex items-center gap-2">
                  <Brain size={20} className="text-blue-400" />
                  Paramètres du modèle
                </h3>

                <div className="space-y-5">
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2 uppercase tracking-wide text-xs">
                      Modèle
                    </label>
                    <input
                      type="text"
                      value={aiConfig?.model || ""}
                      onChange={(e) =>
                        setAiConfig(
                          aiConfig
                            ? { ...aiConfig, model: e.target.value }
                            : null,
                        )
                      }
                      className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-blue-500/50 transition-colors"
                      placeholder="ex: x-ai/grok-4.1-fast:free"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-3 uppercase tracking-wide text-xs">
                      Température: {aiConfig?.temperature.toFixed(1)}
                    </label>
                    <input
                      type="range"
                      min="0"
                      max="2"
                      step="0.1"
                      value={aiConfig?.temperature || 0.7}
                      onChange={(e) =>
                        setAiConfig(
                          aiConfig
                            ? {
                                ...aiConfig,
                                temperature: parseFloat(e.target.value),
                              }
                            : null,
                        )
                      }
                      className="w-full h-2 bg-white/10 rounded-lg appearance-none cursor-pointer accent-blue-500"
                    />
                    <p className="text-xs text-gray-500 mt-2">
                      0 = déterministe | 2 = très créatif
                    </p>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2 uppercase tracking-wide text-xs">
                      Tokens max
                    </label>
                    <input
                      type="number"
                      min="128"
                      max="4096"
                      value={aiConfig?.maxTokens || 2048}
                      onChange={(e) =>
                        setAiConfig(
                          aiConfig
                            ? {
                                ...aiConfig,
                                maxTokens: parseInt(e.target.value, 10),
                              }
                            : null,
                        )
                      }
                      className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-blue-500/50 transition-colors"
                    />
                  </div>
                </div>
              </div>

              {/* System Prompt */}
              <div
                className="rounded-2xl p-6"
                style={{
                  background: "rgba(17, 17, 17, 0.6)",
                  border: "1px solid rgba(255, 255, 255, 0.08)",
                  boxShadow: "0 8px 32px rgba(0, 0, 0, 0.4)",
                }}
              >
                <h3 className="text-lg font-semibold text-white mb-6 flex items-center gap-2">
                  <Settings size={20} className="text-purple-400" />
                  Prompt système
                </h3>

                <textarea
                  value={aiConfig?.systemPrompt || ""}
                  onChange={(e) =>
                    setAiConfig(
                      aiConfig
                        ? { ...aiConfig, systemPrompt: e.target.value }
                        : null,
                    )
                  }
                  rows={8}
                  className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-blue-500/50 transition-colors resize-none"
                  placeholder="Entrez les instructions pour l'IA..."
                />
              </div>
            </div>

            {/* Save Button */}
            <div className="flex justify-end">
              <button
                onClick={handleSaveAiConfig}
                disabled={savingAiConfig}
                className="flex items-center gap-2 px-6 py-3 rounded-2xl font-semibold text-sm transition-all duration-200"
                style={{
                  background: savingAiConfig
                    ? "rgba(59, 130, 246, 0.5)"
                    : "linear-gradient(135deg, #3b82f6 0%, #2563eb 100%)",
                  color: "white",
                  boxShadow: "0 8px 16px rgba(59, 130, 246, 0.3)",
                }}
                onMouseEnter={(e) => {
                  if (!savingAiConfig) {
                    e.currentTarget.style.transform = "translateY(-2px)";
                    e.currentTarget.style.boxShadow = "0 12px 20px rgba(59, 130, 246, 0.4)";
                  }
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.transform = "translateY(0)";
                  e.currentTarget.style.boxShadow = "0 8px 16px rgba(59, 130, 246, 0.3)";
                }}
              >
                <Save size={18} />
                {savingAiConfig ? "Sauvegarde..." : "Sauvegarder"}
              </button>
            </div>
          </div>
        )}

        {activeTab === "system" && (
          <div className="space-y-6">
            {/* Header */}
            <div>
              <h2 className="text-xl font-bold text-white mb-2">Gestion système</h2>
              <p className="text-gray-400 text-sm">Bans, maintenances et notifications globales</p>
            </div>

            <AdminBanManagement users={users} />

            {/* Maintenance Mode */}
            <div
              className="rounded-2xl p-6"
              style={{
                background: "rgba(17, 17, 17, 0.6)",
                border: "1px solid rgba(234, 179, 8, 0.2)",
                boxShadow: "0 8px 32px rgba(0, 0, 0, 0.4)",
              }}
            >
              <h3 className="text-lg font-semibold text-white mb-6 flex items-center gap-2">
                <Clock size={20} className="text-yellow-500" />
                Mode maintenance
              </h3>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Form */}
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2 uppercase tracking-wide text-xs">
                      Titre
                    </label>
                    <input
                      type="text"
                      value={maintenanceTitle}
                      onChange={(e) => setMaintenanceTitle(e.target.value)}
                      className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-yellow-500/50 transition-colors"
                      placeholder="ex: Mise à jour système"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2 uppercase tracking-wide text-xs">
                      Message
                    </label>
                    <textarea
                      value={maintenanceMessage}
                      onChange={(e) => setMaintenanceMessage(e.target.value)}
                      rows={3}
                      className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-yellow-500/50 transition-colors resize-none"
                      placeholder="Entrez le message de maintenance..."
                    />
                  </div>

                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="block text-sm font-medium text-gray-300 mb-2 uppercase tracking-wide text-xs">
                        Durée (min)
                      </label>
                      <input
                        type="number"
                        min="1"
                        value={maintenanceDuration}
                        onChange={(e) =>
                          setMaintenanceDuration(parseInt(e.target.value, 10))
                        }
                        className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-yellow-500/50 transition-colors"
                      />
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-300 mb-2 uppercase tracking-wide text-xs">
                        Sévérité
                      </label>
                      <select
                        value={maintenanceSeverity}
                        onChange={(e) =>
                          setMaintenanceSeverity(
                            e.target.value as "info" | "warning" | "critical",
                          )
                        }
                        className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-yellow-500/50 transition-colors"
                      >
                        <option value="info">Info</option>
                        <option value="warning">Avertissement</option>
                        <option value="critical">Critique</option>
                      </select>
                    </div>
                  </div>

                  <button
                    onClick={handleCreateMaintenance}
                    disabled={savingMaintenance}
                    className="w-full flex items-center justify-center gap-2 px-4 py-3 rounded-xl font-semibold text-sm transition-all duration-200"
                    style={{
                      background: savingMaintenance
                        ? "rgba(234, 179, 8, 0.3)"
                        : "rgba(234, 179, 8, 0.2)",
                      border: "1px solid rgba(234, 179, 8, 0.5)",
                      color: "rgb(250, 204, 21)",
                      opacity: savingMaintenance ? 0.5 : 1,
                    }}
                  >
                    <Clock size={18} />
                    {savingMaintenance ? "Création..." : "Démarrer maintenance"}
                  </button>
                </div>

                {/* Active Maintenances */}
                <div className="bg-white/[0.02] rounded-xl p-4 border border-white/10">
                  <h4 className="text-sm font-semibold text-white mb-4">
                    Actives ({maintenanceNotices.filter((n) => n.isActive).length})
                  </h4>
                  <div className="space-y-3 max-h-80 overflow-y-auto">
                    {maintenanceNotices.filter((n) => n.isActive).length ===
                    0 ? (
                      <p className="text-xs text-gray-500">Pas de maintenance</p>
                    ) : (
                      maintenanceNotices
                        .filter((n) => n.isActive)
                        .map((notice) => (
                          <div
                            key={notice.id}
                            className="bg-white/5 border border-yellow-500/20 rounded-lg p-3"
                          >
                            <div className="flex justify-between items-start gap-2">
                              <div className="flex-1 min-w-0">
                                <p className="text-sm text-white font-medium">
                                  {notice.title}
                                </p>
                                <p className="text-xs text-gray-500 mt-1 line-clamp-2">
                                  {notice.message}
                                </p>
                                <p
                                  className={`text-xs font-semibold mt-2 ${
                                    notice.severity === "critical"
                                      ? "text-red-400"
                                      : notice.severity === "warning"
                                        ? "text-yellow-400"
                                        : "text-blue-400"
                                  }`}
                                >
                                  {notice.severity.toUpperCase()}
                                </p>
                              </div>
                              <button
                                onClick={() => handleEndMaintenance(notice.id)}
                                className="px-3 py-1 rounded-lg bg-white/10 hover:bg-white/20 text-gray-400 hover:text-white transition-colors text-xs font-medium whitespace-nowrap"
                              >
                                Terminer
                              </button>
                            </div>
                          </div>
                        ))
                    )}
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Generate License Modal */}
      {userData && (
        <GenerateLicenseModal
          isOpen={showGenerateLicenseModal}
          onClose={() => setShowGenerateLicenseModal(false)}
          adminUid={userData.uid}
          onLicenseGenerated={handleLicenseGenerated}
        />
      )}
    </div>
  );
}
