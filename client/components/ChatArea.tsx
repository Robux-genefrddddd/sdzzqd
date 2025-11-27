import { Send, Smile, Loader2 } from "lucide-react";
import { useState, useEffect, useRef } from "react";
import { useAuth } from "@/contexts/AuthContext";
import { MessagesService, Message } from "@/lib/messages";
import { getStorage, ref, getBytes } from "firebase/storage";
import { AIService } from "@/lib/ai";
import {
  validateMessageContent,
  detectInjectionAttempt,
  sanitizeInput,
  RateLimiter,
  escapeHtml,
} from "@/lib/security";
import { toast } from "sonner";
import { MessageRenderer } from "@/components/MessageRenderer";
import { ThinkingAnimation } from "@/components/ThinkingAnimation";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";

const AUTO_RESIZE_CONFIG = {
  minHeight: 48,
  maxHeight: 200,
};

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
  "����",
  "❤️",
  "✨",
  "🚀",
  "���",
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
  const [generatingImage, setGeneratingImage] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  // Rate limiter: max 30 messages per minute
  const messageRateLimiter = useRef(new RateLimiter("send_message", 30, 60000));

  const handleTextareaAutoResize = () => {
    if (!textareaRef.current) return;
    textareaRef.current.style.height = `${AUTO_RESIZE_CONFIG.minHeight}px`;
    const scrollHeight = textareaRef.current.scrollHeight;
    const newHeight = Math.min(
      scrollHeight,
      AUTO_RESIZE_CONFIG.maxHeight,
    );
    textareaRef.current.style.height = `${newHeight}px`;
  };

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

    // Rate limiting check
    if (!messageRateLimiter.current.isAllowed()) {
      toast.error(
        "Trop de messages. Veuillez attendre avant d'envoyer un nouveau message.",
      );
      return;
    }

    // Validate message content
    if (!validateMessageContent(message)) {
      toast.error("Message invalide. Longueur: 1-5000 caractères.");
      return;
    }

    // Detect injection attempts
    if (detectInjectionAttempt(message)) {
      toast.error("Message contains invalid characters or patterns.");
      return;
    }

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

    // Sanitize message
    const sanitizedMessage = sanitizeInput(message.trim());
    const userMessageText = sanitizedMessage;
    const isImage = isImageRequest(userMessageText);
    setMessage("");
    setLoading(true);
    if (!isImage) setIsThinking(true);
    if (isImage) setGeneratingImage(true);

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

      let assistantContent: string;

      if (isImage) {
        // Generate image
        assistantContent = await generateImage(userMessageText);
      } else {
        // Get AI response for normal chat
        const conversationHistory = chatMessages.map((msg) => ({
          role: msg.role,
          content: msg.content,
        }));

        setIsThinking(false);
        assistantContent = await AIService.sendMessage(
          userMessageText,
          conversationHistory,
        );
      }

      // Add assistant response to chat
      const assistantMsg: ChatMessage = {
        id: (Date.now() + 1).toString(),
        role: "assistant",
        content: assistantContent,
        timestamp: Date.now(),
      };
      setChatMessages((prev) => [...prev, assistantMsg]);

      // Save assistant message to Firebase
      await MessagesService.addMessage(
        conversationId,
        user.uid,
        `assistant:${assistantContent}`,
      );

      // Update message count in Firebase
      await MessagesService.updateUserMessageCount(
        user.uid,
        userData.messagesUsed + 1,
      );

      if (isImage) {
        toast.success("Image générée avec succès!");
      }
    } catch (error) {
      console.error("Error sending message:", error);
      toast.error(
        error instanceof Error ? error.message : "Erreur lors de l'envoi",
      );
    } finally {
      setLoading(false);
      setIsThinking(false);
      setGeneratingImage(false);
    }
  };

  const addEmoji = (emoji: string) => {
    setMessage(message + emoji);
    setEmojiOpen(false);
  };

  const isImageRequest = (text: string): boolean => {
    const imageKeywords = [
      "crée moi une image",
      "génère une image",
      "generate an image",
      "create an image",
      "dessine",
      "draw",
      "peint",
      "paint",
      "image de",
      "image du",
      "image d",
      "picture of",
      "photo of",
      "visual of",
    ];
    const lowerText = text.toLowerCase();
    return imageKeywords.some((keyword) => lowerText.includes(keyword));
  };

  const generateImage = async (prompt: string): Promise<string> => {
    try {
      // Use Pollinations.ai for image generation
      const imageUrl = `https://image.pollinations.ai/prompt/${encodeURIComponent(prompt)}`;
      return imageUrl;
    } catch (error) {
      console.error("Error generating image:", error);
      throw new Error("Erreur lors de la génération d'image");
    }
  };

  return (
    <div
      id="chat-area"
      className="flex-1 flex flex-col bg-[#0e0e0e] min-h-0"
    >
      {/* Main Content Area - Messages Container with Fixed Height & Scrollbar */}
      <div className="flex-1 overflow-y-auto flex flex-col px-6 md:px-8 py-6 animate-fadeIn min-h-0 items-center">
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
          <div className="w-full max-w-2xl space-y-3 pb-4">
            {chatMessages.map((msg) => (
              <div
                key={msg.id}
                className={`flex w-full ${
                  msg.role === "user" ? "justify-end" : "justify-start"
                } animate-springFade`}
              >
                {msg.role === "user" ? (
                  <div className="flex gap-2 items-start flex-row-reverse max-w-lg">
                    <div className="w-8 h-8 rounded-full bg-gradient-to-br from-blue-500 to-blue-600 flex items-center justify-center flex-shrink-0 shadow-md border border-blue-400/50 overflow-hidden">
                      {userData?.profilePhotoURL ? (
                        <img
                          src={userData.profilePhotoURL}
                          alt={user?.displayName || "User"}
                          className="w-full h-full object-cover"
                        />
                      ) : user?.photoURL ? (
                        <img
                          src={user.photoURL}
                          alt={user.displayName || "User"}
                          className="w-full h-full object-cover"
                        />
                      ) : (
                        <span className="text-xs font-bold text-white">
                          {user?.displayName?.[0]?.toUpperCase() || "U"}
                        </span>
                      )}
                    </div>
                    <div className="flex-1 max-w-md max-h-96 overflow-y-auto">
                      <div className="rounded-2xl rounded-tr-none px-4 py-3 text-white/95 text-sm leading-[1.55] break-words" style={{background: 'linear-gradient(135deg, #1E3A8A 0%, #1E40AF 100%)', boxShadow: '0 4px 16px rgba(0, 0, 0, 0.3)'}}>
                        <MessageRenderer
                          content={msg.content}
                          role={msg.role}
                        />
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="flex gap-2 items-start max-w-lg">
                    <div className="w-8 h-8 rounded-full bg-gradient-to-br from-orange-500 to-orange-600 flex items-center justify-center flex-shrink-0 shadow-md border border-orange-400/50">
                      <span className="text-xs font-bold text-white">V</span>
                    </div>
                    <div className="flex-1 max-w-md max-h-96 overflow-y-auto">
                      <div className="rounded-2xl rounded-tl-none px-4 py-3 text-white/90 text-sm leading-[1.55] break-words" style={{backgroundColor: '#111418', border: '1px solid rgba(255, 255, 255, 0.08)', boxShadow: '0 4px 16px rgba(0, 0, 0, 0.3)'}}>
                        <MessageRenderer
                          content={msg.content}
                          role={msg.role}
                        />
                      </div>
                    </div>
                  </div>
                )}
              </div>
            ))}
            {(loading || isThinking) && (
              <div className="flex justify-start animate-springFade w-full">
                <div className="flex gap-2 items-start max-w-lg">
                  <div className="w-8 h-8 rounded-full bg-gradient-to-br from-orange-500 to-orange-600 flex items-center justify-center flex-shrink-0 shadow-md border border-orange-400/50">
                    <span className="text-xs font-bold text-white">V</span>
                  </div>
                  <ThinkingAnimation />
                </div>
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>
        )}
      </div>

      {/* Message Input Area - Fixed at Bottom */}
      <div
        className="w-full px-6 md:px-8 py-6 animate-slideUp border-t"
        style={{ borderColor: 'rgba(255, 255, 255, 0.08)', backgroundColor: '#0e0e0e' }}
      >
        <div className="flex flex-col items-center w-full">
          <div className="w-full max-w-2xl">
            <div
              className={`flex items-end gap-2 px-4 py-3 transition-all duration-300 group shadow-sm ${!conversationId ? "opacity-50 cursor-not-allowed" : "hover:shadow-md focus-within:shadow-md"}`}
              style={{
                backgroundColor: '#111',
                border: '1px solid rgba(255, 255, 255, 0.08)',
                borderRadius: '16px'
              }}
            >
              <textarea
                ref={textareaRef}
                id="message-input"
                value={message}
                onChange={(e) => {
                  setMessage(e.target.value);
                  handleTextareaAutoResize();
                }}
                onKeyPress={(e) => {
                  if (e.key === "Enter" && !e.shiftKey) {
                    e.preventDefault();
                    handleSend();
                  }
                }}
                disabled={!conversationId || loading}
                placeholder={
                  conversationId
                    ? "Votre message..."
                    : "Sélectionnez une conversation..."
                }
                className="flex-1 bg-transparent text-white placeholder-white/50 focus:outline-none text-sm leading-[1.55] disabled:opacity-50 transition-colors resize-none max-h-48"
                style={{
                  height: `${AUTO_RESIZE_CONFIG.minHeight}px`,
                  overflow: 'hidden'
                }}
              />

              {/* Emoji Picker */}
              <Popover open={emojiOpen} onOpenChange={setEmojiOpen}>
                <PopoverTrigger asChild>
                  <button
                    id="emoji-btn"
                    className="p-2 text-white/40 hover:text-white/70 transition-all duration-200 rounded-lg flex-shrink-0"
                    aria-label="Ajouter un emoji"
                  >
                    <Smile size={18} />
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
                className="p-2 text-white/40 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed transition-all duration-200 rounded-lg flex items-center justify-center flex-shrink-0 hover:scale-110 active:scale-95"
                style={{
                  color: !message.trim() ? 'rgba(255, 255, 255, 0.3)' : '#3b82f6'
                }}
                aria-label="Envoyer le message"
              >
                {loading ? (
                  <Loader2 size={18} className="animate-spin" />
                ) : (
                  <Send size={18} />
                )}
              </button>
            </div>
          </div>
        </div>

          {/* Image Generation Loading State */}
          {generatingImage && (
            <div className="flex items-center gap-3 px-4 py-3 mt-2 rounded-lg bg-gradient-to-r from-purple-600/20 to-purple-500/10 border border-purple-500/40 animate-pulse">
            <div className="flex gap-1">
              <div
                className="w-2 h-2 rounded-full bg-purple-400 animate-bounce"
                style={{ animationDelay: "0s" }}
              />
              <div
                className="w-2 h-2 rounded-full bg-purple-400 animate-bounce"
                style={{ animationDelay: "0.2s" }}
              />
              <div
                className="w-2 h-2 rounded-full bg-purple-400 animate-bounce"
                style={{ animationDelay: "0.4s" }}
              />
            </div>
            <span className="text-sm text-purple-300 font-medium">
              Génération d'image en cours...
            </span>
          </div>
        )}
      </div>
    </div>
  );
}
