import { useEffect, useState } from "react";
import {
  doc,
  updateDoc,
} from "firebase/firestore";
import { db, auth } from "@/lib/firebase";
import { useAuth } from "@/contexts/AuthContext";
import {
  Users,
  Edit2,
  Save,
  X,
  Ban,
  AlertCircle,
  TrendingUp,
} from "lucide-react";
import { toast } from "sonner";
import { UserData, PlanType } from "@/contexts/AuthContext";
import { SystemNoticesService } from "@/lib/system-notices";

interface AdminUsersListProps {
  onBanUser?: (email: string) => void;
  onWarnUser?: (email: string) => void;
}

export default function AdminUsersList({
  onBanUser,
  onWarnUser,
}: AdminUsersListProps) {
  const { userData } = useAuth();
  const [users, setUsers] = useState<UserData[]>([]);
  const [loading, setLoading] = useState(true);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editData, setEditData] = useState<Partial<UserData>>({});

  const planLimits: Record<PlanType, number> = {
    Free: 10,
    Classic: 50,
    Pro: 999,
  };

  useEffect(() => {
    loadUsers();
  }, []);

  const loadUsers = async () => {
    try {
      // Get the current user's ID token
      const user = auth.currentUser;

      if (!user) {
        throw new Error("Not authenticated");
      }

      const idToken = await user.getIdToken();

      // Call the backend API to get all users
      const response = await fetch("/api/admin/users", {
        method: "GET",
        headers: {
          "Authorization": `Bearer ${idToken}`,
          "Content-Type": "application/json",
        },
      });

      let data;
      try {
        data = await response.json();
      } catch (parseError) {
        throw new Error("Invalid response from server");
      }

      if (!response.ok) {
        throw new Error(data.message || data.error || "Erreur lors du chargement des utilisateurs");
      }

      const usersList = data.users as UserData[];
      setUsers(usersList);
    } catch (error) {
      console.error("Error loading users:", error);
      toast.error("Erreur lors du chargement des utilisateurs");
    } finally {
      setLoading(false);
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

  const handleQuickBan = async (user: UserData) => {
    onBanUser?.(user.email);
  };

  const handleQuickWarn = async (user: UserData) => {
    onWarnUser?.(user.email);
  };

  return (
    <div className="space-y-6">
      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="p-4 bg-gradient-to-br from-blue-500/10 to-blue-500/5 border border-blue-500/20 rounded-xl hover:border-blue-500/40 transition-all">
          <div className="flex items-center gap-3 mb-2">
            <div className="p-2 bg-blue-500/20 rounded-lg">
              <Users size={18} className="text-blue-400" />
            </div>
            <span className="text-foreground/60 text-xs uppercase font-semibold">
              Utilisateurs
            </span>
          </div>
          <p className="text-2xl font-bold text-white">{users.length}</p>
        </div>

        <div className="p-4 bg-gradient-to-br from-purple-500/10 to-purple-500/5 border border-purple-500/20 rounded-xl hover:border-purple-500/40 transition-all">
          <div className="flex items-center gap-3 mb-2">
            <div className="p-2 bg-purple-500/20 rounded-lg">
              <TrendingUp size={18} className="text-purple-400" />
            </div>
            <span className="text-foreground/60 text-xs uppercase font-semibold">
              Premium
            </span>
          </div>
          <p className="text-2xl font-bold text-white">
            {users.filter((u) => u.plan !== "Free").length}
          </p>
        </div>

      </div>

      {/* Users Table */}
      <div className="bg-white/5 border border-white/10 rounded-xl overflow-hidden">
        <div className="p-6 border-b border-white/10 bg-gradient-to-r from-white/5 to-transparent">
          <h2 className="text-lg font-semibold text-white flex items-center gap-2">
            <Users size={20} />
            Gestion des Utilisateurs ({users.length})
          </h2>
        </div>

        {loading ? (
          <div className="p-8 text-center">
            <p className="text-foreground/60">Chargement...</p>
          </div>
        ) : users.length === 0 ? (
          <div className="p-8 text-center">
            <p className="text-foreground/60">Aucun utilisateur</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="border-b border-white/10 bg-white/[0.02]">
                <tr>
                  <th className="px-6 py-4 text-left text-xs font-semibold text-foreground/70 uppercase">
                    Utilisateur
                  </th>
                  <th className="px-6 py-4 text-left text-xs font-semibold text-foreground/70 uppercase">
                    Plan
                  </th>
                  <th className="px-6 py-4 text-left text-xs font-semibold text-foreground/70 uppercase">
                    Messages
                  </th>
                  <th className="px-6 py-4 text-left text-xs font-semibold text-foreground/70 uppercase">
                    Statut
                  </th>
                  <th className="px-6 py-4 text-left text-xs font-semibold text-foreground/70 uppercase">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody>
                {users.map((user) => (
                  <tr
                    key={user.uid}
                    className="border-b border-white/10 hover:bg-white/5 transition-colors group"
                  >
                    <td className="px-6 py-4">
                      <div>
                        <p className="text-white font-medium">{user.email}</p>
                        <p className="text-xs text-foreground/50 mt-1">
                          ID: {user.uid.substring(0, 12)}...
                        </p>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      {editingId === user.uid ? (
                        <select
                          value={editData.plan || user.plan || "Free"}
                          onChange={(e) => {
                            const plan = e.target.value as PlanType;
                            setEditData({
                              ...editData,
                              plan,
                              messagesLimit: planLimits[plan],
                            });
                          }}
                          className="bg-white/10 border border-white/20 rounded px-3 py-2 text-white text-sm"
                        >
                          <option value="Free">Free</option>
                          <option value="Classic">Classic</option>
                          <option value="Pro">Pro</option>
                        </select>
                      ) : (
                        <span className="text-foreground/70 text-sm font-medium">
                          {user.plan}
                        </span>
                      )}
                    </td>
                    <td className="px-6 py-4">
                      {editingId === user.uid ? (
                        <input
                          type="number"
                          value={
                            editData.messagesUsed || user.messagesUsed || 0
                          }
                          onChange={(e) =>
                            setEditData({
                              ...editData,
                              messagesUsed: parseInt(e.target.value, 10) || 0,
                            })
                          }
                          className="bg-white/10 border border-white/20 rounded px-3 py-2 text-white text-sm w-24"
                        />
                      ) : (
                        <div className="text-sm">
                          <span className="text-white font-medium">
                            {user.messagesUsed}
                          </span>
                          <span className="text-foreground/50 mx-1">/</span>
                          <span className="text-foreground/50">
                            {user.messagesLimit}
                          </span>
                        </div>
                      )}
                    </td>
                    <td className="px-6 py-4">
                      {editingId === user.uid ? (
                        <input
                          type="checkbox"
                          checked={editData.isAdmin || user.isAdmin || false}
                          onChange={(e) =>
                            setEditData({
                              ...editData,
                              isAdmin: e.target.checked,
                            })
                          }
                          className="w-4 h-4"
                        />
                      ) : (
                        <span
                          className={`text-xs font-semibold px-2 py-1 rounded ${
                            user.isAdmin
                              ? "bg-purple-500/20 text-purple-400"
                              : "bg-white/10 text-foreground/50"
                          }`}
                        >
                          {user.isAdmin ? "Admin" : "User"}
                        </span>
                      )}
                    </td>
                    <td className="px-6 py-4">
                      {editingId === user.uid ? (
                        <div className="flex gap-2">
                          <button
                            onClick={handleSaveUser}
                            className="p-2 bg-green-500/20 hover:bg-green-500/30 rounded text-green-400 transition-colors"
                            title="Sauvegarder"
                          >
                            <Save size={16} />
                          </button>
                          <button
                            onClick={() => setEditingId(null)}
                            className="p-2 bg-white/10 hover:bg-white/20 rounded text-white transition-colors"
                            title="Annuler"
                          >
                            <X size={16} />
                          </button>
                        </div>
                      ) : (
                        <div className="flex gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                          <button
                            onClick={() => handleQuickWarn(user)}
                            className="p-2 bg-yellow-500/20 hover:bg-yellow-500/30 rounded text-yellow-400 transition-colors"
                            title="Avertir"
                          >
                            <AlertCircle size={16} />
                          </button>
                          <button
                            onClick={() => handleQuickBan(user)}
                            className="p-2 bg-red-500/20 hover:bg-red-500/30 rounded text-red-400 transition-colors"
                            title="Bannir"
                          >
                            <Ban size={16} />
                          </button>
                          <button
                            onClick={() => handleEditUser(user)}
                            className="p-2 bg-white/10 hover:bg-white/20 rounded text-white transition-colors"
                            title="Éditer"
                          >
                            <Edit2 size={16} />
                          </button>
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
