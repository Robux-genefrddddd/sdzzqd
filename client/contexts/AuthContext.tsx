import { createContext, useContext, useEffect, useState } from "react";
import { User, onAuthStateChanged } from "firebase/auth";
import {
  doc,
  getDoc,
  updateDoc,
  collection,
  query,
  where,
  onSnapshot,
} from "firebase/firestore";
import { auth, db } from "@/lib/firebase";
import {
  SystemNoticesService,
  UserBan,
  MaintenanceNotice,
} from "@/lib/system-notices";

export type PlanType = "Free" | "Classic" | "Pro";
export type UserRole = "user" | "moderator" | "admin";
export type UserCategory =
  | "individual"
  | "business"
  | "organization"
  | "developer";

export interface UserData {
  uid: string;
  email: string;
  displayName: string;
  plan: PlanType;
  role: UserRole;
  category: UserCategory;
  messagesUsed: number;
  messagesLimit: number;
  createdAt: number;
  isAdmin: boolean;
  licenseKey?: string;
  licenseExpiresAt?: number;
  lastMessageReset?: number;
  profilePhotoURL?: string;
  disclaimerAccepted?: boolean;
  disclaimerAcceptedAt?: number;
}

interface AuthContextType {
  user: User | null;
  userData: UserData | null;
  loading: boolean;
  error: string | null;
  isAdmin: boolean;
  userBan: UserBan | null;
  maintenanceNotice: MaintenanceNotice | null;
}

const AuthContext = createContext<AuthContextType>({
  user: null,
  userData: null,
  loading: true,
  error: null,
  isAdmin: false,
});

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [userData, setUserData] = useState<UserData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [userBan, setUserBan] = useState<UserBan | null>(null);
  const [maintenanceNotice, setMaintenanceNotice] =
    useState<MaintenanceNotice | null>(null);

  // Real-time listener for maintenance notices
  useEffect(() => {
    let isMounted = true;
    let unsubscribeMaintenance: (() => void) | null = null;

    const setupMaintenanceListener = async () => {
      try {
        const maintenanceQuery = query(
          collection(db, "maintenance_notices"),
          where("isActive", "==", true),
        );

        unsubscribeMaintenance = onSnapshot(
          maintenanceQuery,
          (snapshot) => {
            if (!isMounted) return;

            if (snapshot.empty) {
              setMaintenanceNotice(null);
            } else {
              const noticeDoc = snapshot.docs[0];
              const notice = {
                id: noticeDoc.id,
                ...noticeDoc.data(),
              } as MaintenanceNotice;

              // Check if maintenance has expired
              if (notice.endTime && notice.endTime.toDate() < new Date()) {
                setMaintenanceNotice(null);
              } else {
                setMaintenanceNotice(notice);
              }
            }
          },
          (error) => {
            console.error("Error listening to maintenance notices:", error);
            // Fallback: try to load once
            if (isMounted) {
              SystemNoticesService.getActiveMaintenanceNotice()
                .then((notice) => {
                  if (isMounted) {
                    setMaintenanceNotice(notice);
                  }
                })
                .catch((err) => {
                  console.error("Fallback maintenance load failed:", err);
                });
            }
          },
        );
      } catch (error) {
        console.error("Failed to set up maintenance listener:", error);
        // Fallback: try to load once
        if (isMounted) {
          SystemNoticesService.getActiveMaintenanceNotice()
            .then((notice) => {
              if (isMounted) {
                setMaintenanceNotice(notice);
              }
            })
            .catch((err) => {
              console.error("Fallback maintenance load failed:", err);
            });
        }
      }
    };

    setupMaintenanceListener();

    return () => {
      isMounted = false;
      if (unsubscribeMaintenance) {
        unsubscribeMaintenance();
      }
    };
  }, []);

  // Auth state listener
  useEffect(() => {
    let isMounted = true;

    const unsubscribe = onAuthStateChanged(auth, async (authUser) => {
      try {
        if (!isMounted) return;

        if (authUser) {
          setUser(authUser);

          // Check if user is banned
          const ban = await SystemNoticesService.getUserBan(authUser.uid);
          if (isMounted) {
            setUserBan(ban);
          }

          const userDocRef = doc(db, "users", authUser.uid);
          const userDocSnap = await getDoc(userDocRef);

          if (!isMounted) return;

          if (userDocSnap.exists()) {
            const userData = userDocSnap.data() as UserData;

            // Trigger daily reset check on server
            if (userData.licenseKey && userData.lastMessageReset) {
              try {
                await fetch("/api/daily-reset", {
                  method: "POST",
                  headers: { "Content-Type": "application/json" },
                  body: JSON.stringify({ userId: authUser.uid }),
                });
              } catch (error) {
                console.error("Error checking daily reset:", error);
              }
            }

            // Check if license has expired
            if (
              userData.licenseExpiresAt &&
              userData.licenseExpiresAt <= Date.now()
            ) {
              // License expired, reset to Free plan
              await updateDoc(userDocRef, {
                plan: "Free",
                messagesLimit: 10,
                messagesUsed: 0,
                licenseKey: "",
                licenseExpiresAt: undefined,
              });
              userData.plan = "Free";
              userData.messagesLimit = 10;
              userData.messagesUsed = 0;
              userData.licenseKey = "";
              userData.licenseExpiresAt = undefined;
            }

            setUserData(userData);
          } else {
            // Initialize new user with Free plan
            const newUserData: UserData = {
              uid: authUser.uid,
              email: authUser.email || "",
              displayName: authUser.displayName || "Utilisateur",
              plan: "Free",
              role: "user",
              category: "individual",
              messagesUsed: 0,
              messagesLimit: 10,
              createdAt: Date.now(),
              isAdmin: false,
            };
            setUserData(newUserData);
          }
        } else {
          setUser(null);
          setUserData(null);
          setUserBan(null);
          setMaintenanceNotice(null);
        }
      } catch (err) {
        if (!isMounted) return;
        setError(err instanceof Error ? err.message : "Auth error");
      } finally {
        if (isMounted) {
          setLoading(false);
        }
      }
    });

    return () => {
      isMounted = false;
      unsubscribe();
    };
  }, []);

  useEffect(() => {
    if (!user) return;

    let isMounted = true;
    let timeoutId: NodeJS.Timeout;

    const refreshUserData = async () => {
      if (!isMounted) return;

      try {
        const userDocRef = doc(db, "users", user.uid);
        const userDocSnap = await getDoc(userDocRef);

        if (isMounted && userDocSnap.exists()) {
          setUserData(userDocSnap.data() as UserData);
        }
      } catch (err) {
        if (isMounted) {
          console.error("Error refreshing user data:", err);
        }
      }

      if (isMounted) {
        timeoutId = setTimeout(refreshUserData, 5000);
      }
    };

    timeoutId = setTimeout(refreshUserData, 5000);

    return () => {
      isMounted = false;
      clearTimeout(timeoutId);
    };
  }, [user]);

  return (
    <AuthContext.Provider
      value={{
        user,
        userData,
        loading,
        error,
        isAdmin: userData?.isAdmin || false,
        userBan,
        maintenanceNotice,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within AuthProvider");
  }
  return context;
}
