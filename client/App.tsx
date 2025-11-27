import "./global.css";

import { Toaster } from "@/components/ui/toaster";
import { createRoot } from "react-dom/client";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  BrowserRouter,
  Routes,
  Route,
  Navigate,
  useNavigate,
} from "react-router-dom";
import { AuthProvider, useAuth } from "@/contexts/AuthContext";
import { ThemeProvider } from "@/contexts/ThemeContext";
import { TOSProvider, useTOS } from "@/contexts/TOSContext";
import { Loader2 } from "lucide-react";
import { useEffect } from "react";
import { toast } from "sonner";
import Index from "./pages/Index";
import NotFound from "./pages/NotFound";
import Login from "./pages/Login";
import Register from "./pages/Register";
import Admin from "./pages/Admin";
import { BanModal } from "@/components/BanModal";
import TOSModal from "@/components/TOSModal";

const queryClient = new QueryClient();

function ProtectedRoute({ element }: { element: React.ReactNode }) {
  const { user, loading, userBan } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <Loader2 className="w-8 h-8 animate-spin text-white" />
      </div>
    );
  }

  if (user && userBan && userBan.type === "ban") {
    return <BanModal ban={userBan} />;
  }

  return user ? element : <Navigate to="/login" replace />;
}

function AdminRoute({ element }: { element: React.ReactNode }) {
  const { user, userData, loading } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <Loader2 className="w-8 h-8 animate-spin text-white" />
      </div>
    );
  }

  return user && userData?.isAdmin ? element : <Navigate to="/" replace />;
}

function AuthPages() {
  const { user } = useAuth();
  return user ? <Navigate to="/" replace /> : <></>;
}

function AppRoutes() {
  const navigate = useNavigate();
  const { userData } = useAuth();
  const { showTOS, acceptTOS } = useTOS();

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === "A") {
        e.preventDefault();
        if (userData?.isAdmin) {
          navigate("/admin");
          toast.success("Accès au panneau admin");
        } else {
          toast.error("Vous n'êtes pas administrateur");
        }
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [navigate, userData?.isAdmin]);

  return (
    <>
      <TOSModal
        isOpen={showTOS}
        onAccept={() => {
          acceptTOS();
          toast.success("Conditions d'utilisation acceptées!");
        }}
        onReject={() => {
          toast.info("Vous devez accepter les conditions pour continuer");
        }}
      />
      <Routes>
        <Route
          path="/login"
          element={
            <>
              <AuthPages />
              <Login />
            </>
          }
        />
        <Route
          path="/register"
          element={
            <>
              <AuthPages />
              <Register />
            </>
          }
        />
        <Route path="/admin" element={<AdminRoute element={<Admin />} />} />
        <Route path="/" element={<ProtectedRoute element={<Index />} />} />
        {/* ADD ALL CUSTOM ROUTES ABOVE THE CATCH-ALL "*" ROUTE */}
        <Route path="*" element={<NotFound />} />
      </Routes>
    </>
  );
}

const App = () => (
  <QueryClientProvider client={queryClient}>
    <TooltipProvider>
      <AuthProvider>
        <ThemeProvider>
          <TOSProvider>
            <Toaster />
            <Sonner />
            <BrowserRouter
              future={{ v7_startTransition: true, v7_relativeSplatPath: true }}
            >
              <AppRoutes />
            </BrowserRouter>
          </TOSProvider>
        </ThemeProvider>
      </AuthProvider>
    </TooltipProvider>
  </QueryClientProvider>
);

createRoot(document.getElementById("root")!).render(<App />);
