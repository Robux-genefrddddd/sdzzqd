import { Send, Smile, Loader2 } from "lucide-react";
import { useState, useEffect, useRef } from "react";
import { useAuth } from "@/contexts/AuthContext";
import { MessagesService, Message } from "@/lib/messages";
import { AIService } from "@/lib/ai";
import { toast } from "sonner";
import { MessageRenderer } from "@/components/MessageRenderer";
import { ThinkingAnimation } from "@/components/ThinkingAnimation";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";

const EMOJIS = [
  "😀",
  "😂",
  "😍",
  "🥰",
  "😎",
  "🤔",
  "😢",
  "😡",
  "🎉",
  "🔥",
  "👍",
  "❤️",
  "✨",
  "🚀",
  "💯",
];

interface ChatMessage {
  id: string;
  role: "user" | "assistant";
  content: string;
  timestamp: number;
}

interface ChatAreaProps {
  conversationId?: string;
}

export function ChatArea({ conversationId }: ChatAreaProps) {
  const { user, userData } = useAuth();
  const [message, setMessage] = useState("");
  const [emojiOpen, setEmojiOpen] = useState(false);
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);
  const [loading, setLoading] = useState(false);
  const [loadingMessages, setLoadingMessages] = useState(false);
  const [isThinking, setIsThinking] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (conversationId && user?.uid) {
      loadMessages();
    }
  }, [conversationId, user?.uid]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [chatMessages, loading, isThinking]);

  const loadMessages = async () => {
    if (!conversationId) return;
    try {
      setLoadingMessages(true);
      const fbMessages = await MessagesService.getMessages(conversationId);
      const messages: ChatMessage[] = fbMessages.map((msg) => ({
        id: msg.id,
        role: msg.text.startsWith("user:") ? "user" : "assistant",
        content: msg.text.replace(/^(user:|assistant:)/, ""),
        timestamp: msg.createdAt.toDate().getTime(),
      }));
      setChatMessages(messages);
    } catch (error) {
      console.error("Error loading messages:", error);
      if (error instanceof Error) {
        console.error("Error message:", error.message);
        if (error.message.includes("Failed to fetch")) {
          toast.error("Erreur réseau. Vérifiez votre connexion.");
        } else {
          toast.error("Erreur lors du chargement des messages");
        }
      } else {
        toast.error("Erreur lors du chargement des messages");
      }
    } finally {
      setLoadingMessages(false);
    }
  };

  const handleSend = async () => {
    if (!message.trim() || !user || !userData || !conversationId) return;

    // Check message limit
    if (userData.messagesUsed >= userData.messagesLimit) {
      toast.error(
        "Limite de messages atteinte. Vous serez redirigé pour activer une licence.",
      );
      return;
    }

    // Warn when getting close to limit (90%)
    const percentUsed = (userData.messagesUsed / userData.messagesLimit) * 100;
    if (percentUsed >= 90) {
      toast.warning(
        `Attention: ${userData.messagesLimit - userData.messagesUsed} messages restants`,
      );
    }

    const userMessageText = message;
    setMessage("");
    setLoading(true);
    setIsThinking(true);

    try {
      // Add user message to chat
      const userMsg: ChatMessage = {
        id: Date.now().toString(),
        role: "user",
        content: userMessageText,
        timestamp: Date.now(),
      };
      setChatMessages((prev) => [...prev, userMsg]);

      // Save user message to Firebase
      await MessagesService.addMessage(
        conversationId,
        user.uid,
        `user:${userMessageText}`,
      );

      // Get AI response
      const conversationHistory = chatMessages.map((msg) => ({
        role: msg.role,
        content: msg.content,
      }));

      setIsThinking(false);
      const aiResponse = await AIService.sendMessage(
        userMessageText,
        conversationHistory,
      );

      // Add AI response to chat
      const assistantMsg: ChatMessage = {
        id: (Date.now() + 1).toString(),
        role: "assistant",
        content: aiResponse,
        timestamp: Date.now(),
      };
      setChatMessages((prev) => [...prev, assistantMsg]);

      // Save assistant message to Firebase
      await MessagesService.addMessage(
        conversationId,
        user.uid,
        `assistant:${aiResponse}`,
      );

      // Update message count in Firebase
      await MessagesService.updateUserMessageCount(
        user.uid,
        userData.messagesUsed + 1,
      );
    } catch (error) {
      console.error("Error sending message:", error);
      toast.error(
        error instanceof Error ? error.message : "Erreur lors de l'envoi",
      );
    } finally {
      setLoading(false);
      setIsThinking(false);
    }
  };

  const addEmoji = (emoji: string) => {
    setMessage(message + emoji);
    setEmojiOpen(false);
  };

  return (
    <div id="chat-area" className="flex-1 flex flex-col bg-gradient-to-b from-background via-background to-background/95">
      {/* Main Content Area */}
      <div className="flex-1 overflow-y-auto flex flex-col px-8 py-6 animate-fadeIn">
        {!conversationId ? (
          <div className="flex-1 flex items-center justify-center">
            <div className="text-center">
              <div
                className="w-20 h-20 rounded-full mx-auto mb-6 flex items-center justify-center border-2 border-foreground/20 animate-scaleIn"
                style={{
                  backgroundImage:
                    "url(https://cdn.builder.io/api/v1/image/assets%2Fafa67d28f8874020a08a6dc1ed05801d%2F340d671f0c4b45db8b30096668d2bc7c)",
                  backgroundRepeat: "no-repeat",
                  backgroundPosition: "center",
                  backgroundSize: "cover",
                }}
              />
              <h2 className="text-lg font-semibold text-foreground mb-2 animate-slideUp">
                Sélectionnez une conversation
              </h2>
              <p
                className="text-sm text-foreground/60 animate-slideUp"
                style={{ animationDelay: "0.1s" }}
              >
                Cliquez sur une conversation à gauche pour commencer
              </p>
            </div>
          </div>
        ) : loadingMessages ? (
          <div className="flex-1 flex items-center justify-center">
            <Loader2 className="w-8 h-8 animate-spin text-foreground/50" />
          </div>
        ) : chatMessages.length === 0 ? (
          <div className="flex-1 flex items-center justify-center">
            <div className="text-center">
              <div
                className="w-20 h-20 rounded-full mx-auto mb-6 flex items-center justify-center border-2 border-foreground/20 animate-scaleIn"
                style={{
                  backgroundImage:
                    "url(https://cdn.builder.io/api/v1/image/assets%2Fafa67d28f8874020a08a6dc1ed05801d%2F340d671f0c4b45db8b30096668d2bc7c)",
                  backgroundRepeat: "no-repeat",
                  backgroundPosition: "center",
                  backgroundSize: "cover",
                }}
              />
              <h2 className="text-lg font-semibold text-foreground mb-2 animate-slideUp">
                Commencez une conversation
              </h2>
              <p
                className="text-sm text-foreground/60 animate-slideUp"
                style={{ animationDelay: "0.1s" }}
              >
                Tapez un message ci-dessous pour commencer
              </p>
            </div>
          </div>
        ) : (
          <div className="space-y-6 pb-4">
            {chatMessages.map((msg) => (
              <div
                key={msg.id}
                className={`flex ${
                  msg.role === "user" ? "justify-end" : "justify-start"
                } animate-slideUp`}
              >
                {msg.role === "user" ? (
                  <div className="flex gap-3 max-w-2xl items-start">
                    <div className="flex-1 max-w-lg">
                      <div className="rounded-2xl rounded-tr-none bg-gradient-to-br from-blue-600/40 to-blue-700/30 border border-blue-500/30 px-5 py-3 backdrop-blur-sm shadow-lg hover:shadow-xl transition-shadow">
                        <p className="text-white/95 text-sm leading-relaxed break-words">
                          <MessageRenderer content={msg.content} role={msg.role} />
                        </p>
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="flex gap-3 max-w-2xl items-start">
                    <div className="w-8 h-8 rounded-full bg-gradient-to-br from-orange-500 to-orange-600 flex items-center justify-center flex-shrink-0 mt-1 shadow-md">
                      <span className="text-xs font-bold text-white">G</span>
                    </div>
                    <div className="flex-1 max-w-lg">
                      <div className="rounded-2xl rounded-tl-none bg-gradient-to-br from-slate-800/50 to-slate-900/50 border border-white/10 px-5 py-4 backdrop-blur-sm shadow-lg hover:shadow-xl transition-shadow">
                        <p className="text-white/90 text-sm leading-relaxed break-words">
                          <MessageRenderer content={msg.content} role={msg.role} />
                        </p>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            ))}
            {(loading || isThinking) && (
              <div className="flex justify-start animate-slideUp">
                <div className="flex gap-3 items-start">
                  <div className="w-8 h-8 rounded-full bg-gradient-to-br from-orange-500 to-orange-600 flex items-center justify-center flex-shrink-0 mt-1 shadow-md">
                    <span className="text-xs font-bold text-white">G</span>
                  </div>
                  <ThinkingAnimation />
                </div>
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>
        )}
      </div>

      {/* Message Input Area */}
      <div
        className="px-8 py-6 animate-slideUp"
        style={{ animationDelay: "0.2s" }}
      >
        <div
          className={`flex items-center gap-3 border-2 border-white/30 rounded-2xl px-5 py-4 bg-gradient-to-r from-white/5 to-white/8 backdrop-blur-sm transition-all duration-300 group ${!conversationId ? "opacity-50 cursor-not-allowed" : "hover:border-white/50 hover:bg-gradient-to-r hover:from-white/8 hover:to-white/12 focus-within:border-white/80 focus-within:shadow-lg focus-within:shadow-white/10"}`}
        >
          <input
            id="message-input"
            type="text"
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            onKeyPress={(e) => {
              if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                handleSend();
              }
            }}
            disabled={!conversationId || loading}
            placeholder={
              conversationId ? "Votre message..." : "Sélectionnez une conversation..."
            }
            className="flex-1 bg-transparent text-white placeholder-white/40 focus:outline-none text-sm leading-relaxed disabled:opacity-50 transition-colors"
          />

          {/* Emoji Picker */}
          <Popover open={emojiOpen} onOpenChange={setEmojiOpen}>
            <PopoverTrigger asChild>
              <button
                id="emoji-btn"
                className="p-2 text-white/50 hover:text-white/80 transition-all duration-200 hover:bg-white/10 rounded-lg"
                aria-label="Ajouter un emoji"
              >
                <Smile size={20} />
              </button>
            </PopoverTrigger>
            <PopoverContent className="w-64 p-3 bg-card border border-white/20 rounded-2xl shadow-xl">
              <div className="grid grid-cols-5 gap-2">
                {EMOJIS.map((emoji) => (
                  <button
                    key={emoji}
                    onClick={() => addEmoji(emoji)}
                    className="p-2 hover:bg-white/10 rounded-lg transition-all duration-200 text-xl hover:scale-125 transform"
                  >
                    {emoji}
                  </button>
                ))}
              </div>
            </PopoverContent>
          </Popover>

          {/* Send Button */}
          <button
            onClick={handleSend}
            disabled={loading || !message.trim()}
            className="p-2.5 text-white/60 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed transition-all duration-200 hover:bg-gradient-to-r hover:from-orange-600/40 hover:to-orange-500/30 rounded-lg flex items-center justify-center hover:scale-110 transform disabled:hover:scale-100"
            aria-label="Envoyer le message"
          >
            {loading ? (
              <Loader2 size={20} className="animate-spin" />
            ) : (
              <Send size={20} />
            )}
          </button>
        </div>
      </div>
    </div>
  );
}
