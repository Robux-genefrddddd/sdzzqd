import { useState, useEffect, useMemo } from "react";
import {
  AlertCircle,
  Trash2,
  Clock,
  User,
  MessageSquare,
  Search,
  X,
  Filter,
  Eye,
  EyeOff,
} from "lucide-react";
import { toast } from "sonner";
import { UserData } from "@/contexts/AuthContext";
import { SystemNoticesService, UserBan } from "@/lib/system-notices";

interface AdminBanManagementProps {
  users: UserData[];
}

export default function AdminBanManagement({ users }: AdminBanManagementProps) {
  const [userEmailToBan, setUserEmailToBan] = useState("");
  const [banReason, setBanReason] = useState("");
  const [banDuration, setBanDuration] = useState<number | null>(null);
  const [actionType, setActionType] = useState<"ban" | "warn">("ban");
  const [bans, setBans] = useState<UserBan[]>([]);
  const [loading, setLoading] = useState(false);
  const [savingBan, setSavingBan] = useState(false);

  // Search and filter states
  const [userSearchQuery, setUserSearchQuery] = useState("");
  const [ipSearchQuery, setIPSearchQuery] = useState("");
  const [filterType, setFilterType] = useState<"all" | "ban" | "warn">("all");
  const [showExpired, setShowExpired] = useState(false);

  useEffect(() => {
    loadBans();
  }, []);

  const loadBans = async () => {
    try {
      setLoading(true);
      const allBans = await SystemNoticesService.getAllBans();
      setBans(allBans);
    } catch (error) {
      console.error("Error loading bans:", error);
      toast.error("Erreur lors du chargement des bans");
    } finally {
      setLoading(false);
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
        setSavingBan(false);
        return;
      }

      if (!user.uid) {
        toast.error("Cet utilisateur n'a pas d'ID valide");
        setSavingBan(false);
        return;
      }

      if (actionType === "ban") {
        await SystemNoticesService.banUser(
          user.uid,
          user.email,
          banReason,
          banDuration || undefined,
        );
        toast.success("Utilisateur banni avec succès");
      } else {
        await SystemNoticesService.warnUser(
          user.uid,
          user.email,
          banReason,
          banDuration || undefined,
        );
        toast.success("Utilisateur averti avec succès");
      }

      setUserEmailToBan("");
      setBanReason("");
      setBanDuration(null);
      await loadBans();
    } catch (error) {
      console.error("Error in handleBanUser:", error);
      const errorMessage =
        error instanceof Error ? error.message : "Erreur lors de l'action";
      toast.error(errorMessage);
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
      console.error("Error in handleUnbanUser:", error);
      const errorMessage =
        error instanceof Error ? error.message : "Erreur lors du déban";
      toast.error(errorMessage);
    }
  };

  const handleBanIP = async () => {
    if (!banIPAddress || !banIPReason) {
      toast.error("Entrez une adresse IP et une raison");
      return;
    }

    setSavingIPBan(true);
    try {
      await IPService.banIP(
        banIPAddress,
        banIPReason,
        banIPDuration || undefined,
      );
      toast.success("Adresse IP bannie avec succès");

      setBanIPAddress("");
      setBanIPReason("");
      setBanIPDuration(null);
      await loadBans();
    } catch (error) {
      console.error("Error in handleBanIP:", error);
      const errorMessage =
        error instanceof Error ? error.message : "Erreur lors du ban IP";
      toast.error(errorMessage);
    } finally {
      setSavingIPBan(false);
    }
  };

  const handleUnbanIP = async (ipAddress: string) => {
    try {
      await IPService.unbanIP(ipAddress);
      toast.success("Adresse IP débanni");
      await loadBans();
    } catch (error) {
      console.error("Error in handleUnbanIP:", error);
      const errorMessage =
        error instanceof Error ? error.message : "Erreur lors du déban IP";
      toast.error(errorMessage);
    }
  };

  // Filtered and searched bans
  const filteredUserBans = useMemo(() => {
    let result = bans;

    if (filterType !== "all") {
      result = result.filter((b) => b.type === filterType);
    }

    if (!showExpired) {
      result = result.filter((b) => b.isPermanent || !isExpired(b));
    }

    if (userSearchQuery) {
      result = result.filter((b) =>
        b.email.toLowerCase().includes(userSearchQuery.toLowerCase()),
      );
    }

    return result;
  }, [bans, filterType, showExpired, userSearchQuery]);

  const filteredIPBans = useMemo(() => {
    return ipBans.filter((ban) => ban.ipAddress.includes(ipSearchQuery));
  }, [ipBans, ipSearchQuery]);

  const isExpired = (ban: UserBan) => {
    return ban.expiresAt && ban.expiresAt.toDate() < new Date();
  };

  return (
    <div className="space-y-8">
      {/* Action Type Tabs */}
      <div className="flex gap-3">
        {[
          { id: "warn", label: "Avertir", icon: AlertCircle, color: "yellow" },
          { id: "ban", label: "Bannir", icon: AlertCircle, color: "red" },
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActionType(tab.id as any)}
            className={`flex items-center gap-2 px-4 py-3 rounded-xl font-medium text-sm transition-all duration-200 border ${
              actionType === tab.id
                ? tab.color === "warn"
                  ? "bg-yellow-500/20 border-yellow-500/50 text-yellow-300"
                  : "bg-red-500/20 border-red-500/50 text-red-300"
                : "bg-white/5 border-white/10 text-gray-400 hover:bg-white/10"
            }`}
          >
            <AlertCircle size={16} />
            {tab.label}
          </button>
        ))}
      </div>

      {/* Main Forms */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* User Ban Form */}
        <div
          className="rounded-2xl p-6"
          style={{
            background: "rgba(17, 17, 17, 0.6)",
            border:
              actionType === "ban"
                ? "1px solid rgba(239, 68, 68, 0.2)"
                : "1px solid rgba(234, 179, 8, 0.2)",
            boxShadow: "0 8px 32px rgba(0, 0, 0, 0.4)",
          }}
        >
          <h3 className="text-lg font-semibold text-white mb-6 flex items-center gap-2">
            <AlertCircle
              size={20}
              className={
                actionType === "ban" ? "text-red-500" : "text-yellow-500"
              }
            />
            {actionType === "ban" ? "Bannir" : "Avertir"} un utilisateur
          </h3>

          <div className="space-y-4">
            {/* Email Input with Autocomplete */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2 uppercase tracking-wide text-xs">
                <User size={14} className="inline mr-2" />
                Email de l'utilisateur
              </label>
              <div className="relative">
                <input
                  type="email"
                  value={userEmailToBan}
                  onChange={(e) => setUserEmailToBan(e.target.value)}
                  list="user-emails"
                  className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white placeholder-gray-600 focus:outline-none focus:border-blue-500/50 transition-colors"
                  placeholder="user@example.com"
                  autoComplete="off"
                />
                <datalist id="user-emails">
                  {users
                    ?.filter((u) =>
                      u.email
                        .toLowerCase()
                        .includes(userEmailToBan.toLowerCase()),
                    )
                    .slice(0, 10)
                    .map((user, index) => (
                      <option key={index} value={user.email} />
                    ))}
                </datalist>
                {userEmailToBan && (
                  <button
                    onClick={() => setUserEmailToBan("")}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300"
                  >
                    <X size={16} />
                  </button>
                )}
              </div>
            </div>

            {/* Reason Textarea */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2 uppercase tracking-wide text-xs">
                <MessageSquare size={14} className="inline mr-2" />
                Raison
              </label>
              <textarea
                value={banReason}
                onChange={(e) => setBanReason(e.target.value)}
                rows={4}
                className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white placeholder-gray-600 focus:outline-none focus:border-blue-500/50 transition-colors resize-none"
                placeholder={
                  actionType === "ban"
                    ? "Raison du bannissement..."
                    : "Raison de l'avertissement..."
                }
              />
            </div>

            {/* Duration Input */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2 uppercase tracking-wide text-xs">
                <Clock size={14} className="inline mr-2" />
                Durée (minutes)
              </label>
              <input
                type="number"
                min="1"
                value={banDuration || ""}
                onChange={(e) =>
                  setBanDuration(
                    e.target.value ? parseInt(e.target.value, 10) : null,
                  )
                }
                className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white placeholder-gray-600 focus:outline-none focus:border-blue-500/50 transition-colors"
                placeholder="Laisser vide pour permanent (ex: 1440 = 24h)"
              />
            </div>

            {/* Submit Button */}
            <button
              onClick={handleBanUser}
              disabled={savingBan || !userEmailToBan || !banReason}
              className={`w-full flex items-center justify-center gap-2 px-4 py-3 font-semibold rounded-xl transition-all duration-200 text-sm ${
                actionType === "ban"
                  ? "bg-red-500/20 hover:bg-red-500/30 text-red-300 border border-red-500/50"
                  : "bg-yellow-500/20 hover:bg-yellow-500/30 text-yellow-300 border border-yellow-500/50"
              } disabled:opacity-50 disabled:cursor-not-allowed`}
            >
              <AlertCircle size={18} />
              {savingBan
                ? "Traitement..."
                : actionType === "ban"
                  ? "Bannir l'utilisateur"
                  : "Avertir l'utilisateur"}
            </button>
          </div>
        </div>

        {/* IP Ban Form */}
        <div
          className="rounded-2xl p-6"
          style={{
            background: "rgba(17, 17, 17, 0.6)",
            border: "1px solid rgba(168, 85, 247, 0.2)",
            boxShadow: "0 8px 32px rgba(0, 0, 0, 0.4)",
          }}
        >
          <h3 className="text-lg font-semibold text-white mb-6 flex items-center gap-2">
            <AlertCircle size={20} className="text-purple-500" />
            Bannir une adresse IP
          </h3>

          <div className="space-y-4">
            {/* IP Address Input */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2 uppercase tracking-wide text-xs">
                Adresse IP
              </label>
              <input
                type="text"
                value={banIPAddress}
                onChange={(e) => setBanIPAddress(e.target.value)}
                className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white placeholder-gray-600 focus:outline-none focus:border-blue-500/50 transition-colors font-mono text-sm"
                placeholder="192.168.1.1 ou 2001:db8::1"
              />
            </div>

            {/* Reason Textarea */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2 uppercase tracking-wide text-xs">
                <MessageSquare size={14} className="inline mr-2" />
                Raison
              </label>
              <textarea
                value={banIPReason}
                onChange={(e) => setBanIPReason(e.target.value)}
                rows={4}
                className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white placeholder-gray-600 focus:outline-none focus:border-blue-500/50 transition-colors resize-none"
                placeholder="Raison du bannissement IP..."
              />
            </div>

            {/* Duration Input */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2 uppercase tracking-wide text-xs">
                <Clock size={14} className="inline mr-2" />
                Durée (minutes)
              </label>
              <input
                type="number"
                min="1"
                value={banIPDuration || ""}
                onChange={(e) =>
                  setBanIPDuration(
                    e.target.value ? parseInt(e.target.value, 10) : null,
                  )
                }
                className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white placeholder-gray-600 focus:outline-none focus:border-blue-500/50 transition-colors"
                placeholder="Laisser vide pour permanent"
              />
            </div>

            {/* Submit Button */}
            <button
              onClick={handleBanIP}
              disabled={savingIPBan || !banIPAddress || !banIPReason}
              className="w-full flex items-center justify-center gap-2 px-4 py-3 bg-purple-500/20 hover:bg-purple-500/30 text-purple-300 font-semibold rounded-xl border border-purple-500/50 transition-all duration-200 text-sm disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <AlertCircle size={18} />
              {savingIPBan ? "Traitement..." : "Bannir l'IP"}
            </button>
          </div>
        </div>
      </div>

      {/* User Bans List */}
      <div
        className="rounded-2xl overflow-hidden"
        style={{
          background: "rgba(17, 17, 17, 0.6)",
          border: "1px solid rgba(255, 255, 255, 0.08)",
          boxShadow: "0 8px 32px rgba(0, 0, 0, 0.4)",
        }}
      >
        {/* Header with Search */}
        <div className="p-6 border-b border-white/10 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-lg font-semibold text-white flex items-center gap-2">
              <User size={20} className="text-blue-400" />
              Utilisateurs sanctionn��s ({filteredUserBans.length})
            </h3>
          </div>

          {/* Search and Filters */}
          <div className="flex flex-col sm:flex-row gap-3">
            {/* Search */}
            <div className="flex-1 relative">
              <Search
                size={16}
                className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500"
              />
              <input
                type="text"
                placeholder="Rechercher par email..."
                value={userSearchQuery}
                onChange={(e) => setUserSearchQuery(e.target.value)}
                className="w-full bg-white/5 border border-white/10 rounded-lg pl-10 pr-4 py-2.5 text-white text-sm placeholder-gray-600 focus:outline-none focus:border-blue-500/50 transition-colors"
              />
            </div>

            {/* Filter Type */}
            <select
              value={filterType}
              onChange={(e) => setFilterType(e.target.value as any)}
              className="bg-white/5 border border-white/10 rounded-lg px-3 py-2.5 text-white text-sm focus:outline-none focus:border-blue-500/50 transition-colors"
            >
              <option value="all">Tous</option>
              <option value="ban">Bans</option>
              <option value="warn">Avertissements</option>
            </select>

            {/* Show Expired Toggle */}
            <button
              onClick={() => setShowExpired(!showExpired)}
              className={`px-3 py-2.5 rounded-lg font-medium text-sm transition-all duration-200 border flex items-center gap-2 ${
                showExpired
                  ? "bg-blue-500/20 border-blue-500/50 text-blue-300"
                  : "bg-white/5 border-white/10 text-gray-400 hover:bg-white/10"
              }`}
            >
              {showExpired ? <Eye size={16} /> : <EyeOff size={16} />}
              Expirés
            </button>
          </div>
        </div>

        {/* Bans Table */}
        <div className="overflow-x-auto">
          {loading ? (
            <div className="p-8 text-center">
              <p className="text-gray-500">Chargement...</p>
            </div>
          ) : filteredUserBans.length === 0 ? (
            <div className="p-12 text-center">
              <AlertCircle size={32} className="mx-auto text-gray-600 mb-3" />
              <p className="text-gray-500">Aucune sanction trouvée</p>
            </div>
          ) : (
            <table className="w-full text-sm">
              <thead className="border-b border-white/10 bg-white/[0.02]">
                <tr>
                  <th className="px-6 py-4 text-left font-semibold text-gray-400">
                    Email
                  </th>
                  <th className="px-6 py-4 text-left font-semibold text-gray-400">
                    Type
                  </th>
                  <th className="px-6 py-4 text-left font-semibold text-gray-400">
                    Raison
                  </th>
                  <th className="px-6 py-4 text-left font-semibold text-gray-400">
                    Expire
                  </th>
                  <th className="px-6 py-4 text-left font-semibold text-gray-400">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody>
                {filteredUserBans.map((ban) => {
                  const expired = isExpired(ban);
                  return (
                    <tr
                      key={ban.id}
                      className={`border-b border-white/10 hover:bg-white/5 transition-colors ${
                        expired ? "opacity-50" : ""
                      }`}
                    >
                      <td className="px-6 py-4 text-white font-medium">
                        {ban.email}
                      </td>
                      <td className="px-6 py-4">
                        <span
                          className={`px-3 py-1 rounded-lg text-xs font-semibold ${
                            ban.type === "ban"
                              ? "bg-red-500/20 text-red-400"
                              : "bg-yellow-500/20 text-yellow-400"
                          }`}
                        >
                          {ban.type === "ban" ? "BAN" : "AVERTISSEMENT"}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-gray-400 text-sm truncate max-w-xs">
                        {ban.reason}
                      </td>
                      <td className="px-6 py-4 text-gray-500 text-sm">
                        {ban.isPermanent
                          ? "Permanent"
                          : ban.expiresAt
                            ? new Date(
                                ban.expiresAt.toDate(),
                              ).toLocaleDateString("fr-FR")
                            : "-"}
                      </td>
                      <td className="px-6 py-4">
                        <button
                          onClick={() => handleUnbanUser(ban.userId)}
                          className="px-3 py-1.5 rounded-lg bg-white/10 hover:bg-red-500/20 text-gray-400 hover:text-red-400 transition-colors text-xs font-medium"
                        >
                          <Trash2 size={14} className="inline mr-1" />
                          Retirer
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* IP Bans List */}
      <div
        className="rounded-2xl overflow-hidden"
        style={{
          background: "rgba(17, 17, 17, 0.6)",
          border: "1px solid rgba(255, 255, 255, 0.08)",
          boxShadow: "0 8px 32px rgba(0, 0, 0, 0.4)",
        }}
      >
        {/* Header with Search */}
        <div className="p-6 border-b border-white/10 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-lg font-semibold text-white flex items-center gap-2">
              <AlertCircle size={20} className="text-purple-400" />
              Adresses IP bannies ({filteredIPBans.length})
            </h3>
          </div>

          {/* Search */}
          <div className="relative">
            <Search
              size={16}
              className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500"
            />
            <input
              type="text"
              placeholder="Rechercher par IP..."
              value={ipSearchQuery}
              onChange={(e) => setIPSearchQuery(e.target.value)}
              className="w-full bg-white/5 border border-white/10 rounded-lg pl-10 pr-4 py-2.5 text-white text-sm placeholder-gray-600 focus:outline-none focus:border-blue-500/50 transition-colors"
            />
          </div>
        </div>

        {/* IPs Table */}
        <div className="overflow-x-auto">
          {ipBans.length === 0 ? (
            <div className="p-12 text-center">
              <AlertCircle size={32} className="mx-auto text-gray-600 mb-3" />
              <p className="text-gray-500">Aucune IP bannie</p>
            </div>
          ) : filteredIPBans.length === 0 ? (
            <div className="p-8 text-center">
              <p className="text-gray-500">Aucune IP trouvée</p>
            </div>
          ) : (
            <table className="w-full text-sm">
              <thead className="border-b border-white/10 bg-white/[0.02]">
                <tr>
                  <th className="px-6 py-4 text-left font-semibold text-gray-400">
                    Adresse IP
                  </th>
                  <th className="px-6 py-4 text-left font-semibold text-gray-400">
                    Raison
                  </th>
                  <th className="px-6 py-4 text-left font-semibold text-gray-400">
                    Expire
                  </th>
                  <th className="px-6 py-4 text-left font-semibold text-gray-400">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody>
                {filteredIPBans.map((ban) => (
                  <tr
                    key={`ip-ban-${ban.id}`}
                    className="border-b border-white/10 hover:bg-white/5 transition-colors"
                  >
                    <td className="px-6 py-4 text-white font-mono font-medium">
                      {ban.ipAddress}
                    </td>
                    <td className="px-6 py-4 text-gray-400 text-sm truncate max-w-xs">
                      {ban.reason}
                    </td>
                    <td className="px-6 py-4 text-gray-500 text-sm">
                      {ban.isPermanent
                        ? "Permanent"
                        : ban.expiresAt
                          ? new Date(ban.expiresAt).toLocaleDateString("fr-FR")
                          : "-"}
                    </td>
                    <td className="px-6 py-4">
                      <button
                        onClick={() => handleUnbanIP(ban.ipAddress)}
                        className="px-3 py-1.5 rounded-lg bg-white/10 hover:bg-purple-500/20 text-gray-400 hover:text-purple-400 transition-colors text-xs font-medium"
                      >
                        <Trash2 size={14} className="inline mr-1" />
                        Retirer
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}
