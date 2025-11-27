import { Loader2 } from "lucide-react";
import { useState, useEffect, useRef } from "react";
import { useAuth } from "@/contexts/AuthContext";
import { useTheme } from "@/contexts/ThemeContext";
import { MessagesService, Message } from "@/lib/messages";
import { getStorage, ref, getBytes } from "firebase/storage";
import { AIService } from "@/lib/ai";
import { splitIntoBlocks, getBlockPauseDuration } from "@/lib/blockSplitter";
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
import { TypingIndicator } from "@/components/TypingIndicator";
import { ChatInput } from "@/components/ChatInput";

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
  const { isDark } = useTheme();
  const [message, setMessage] = useState("");
  const [emojiOpen, setEmojiOpen] = useState(false);
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);
  const [loading, setLoading] = useState(false);
  const [loadingMessages, setLoadingMessages] = useState(false);
  const [isThinking, setIsThinking] = useState(false);
  const [generatingImage, setGeneratingImage] = useState(false);
  const [isTyping, setIsTyping] = useState(false);
  const [typingText, setTypingText] = useState("");
  const [fullText, setFullText] = useState("");
  const [blocks, setBlocks] = useState<string[]>([]);
  const [renderedBlockCount, setRenderedBlockCount] = useState(0);
  const [isRenderingBlocks, setIsRenderingBlocks] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const typingIntervalRef = useRef<NodeJS.Timeout | null>(null);
  const blockIntervalRef = useRef<NodeJS.Timeout | null>(null);

  // Rate limiter: max 30 messages per minute
  const messageRateLimiter = useRef(new RateLimiter("send_message", 30, 60000));


  const getCharacterDelay = (char: string, nextChar?: string): number => {
    const baseDelay = 20;
    if (char === "." || char === "?" || char === "!") {
      return 200;
    }
    if (char === ",") {
      return 80;
    }
    if (char === "\n") {
      return 100;
    }
    return baseDelay;
  };

  const startTypewriterEffect = (text: string) => {
    if (typingIntervalRef.current) {
      clearInterval(typingIntervalRef.current);
    }

    setIsTyping(true);
    setTypingText("");
    setFullText(text);
    let currentIndex = 0;

    const typeNextCharacter = () => {
      if (currentIndex < text.length) {
        const newText = text.substring(0, currentIndex + 1);
        setTypingText(newText);
        messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });

        const currentChar = text[currentIndex];
        const delay = getCharacterDelay(currentChar);

        typingIntervalRef.current = setTimeout(
          typeNextCharacter,
          delay,
        ) as unknown as NodeJS.Timeout;

        currentIndex++;
      } else {
        setIsTyping(false);
        typingIntervalRef.current = null;
      }
    };

    typingIntervalRef.current = setTimeout(
      typeNextCharacter,
      20,
    ) as unknown as NodeJS.Timeout;
  };

  const startBlockRendering = (fullText: string) => {
    if (typingIntervalRef.current) {
      clearTimeout(typingIntervalRef.current);
    }
    if (blockIntervalRef.current) {
      clearTimeout(blockIntervalRef.current);
    }

    setFullText(fullText);
    const textBlocks = splitIntoBlocks(fullText);
    setBlocks(textBlocks);
    setRenderedBlockCount(0);
    setIsRenderingBlocks(true);
    setIsTyping(false);

    let blockIndex = 0;

    const renderNextBlock = () => {
      if (blockIndex < textBlocks.length) {
        setRenderedBlockCount(blockIndex + 1);
        messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });

        const currentBlockLength = textBlocks[blockIndex].length;
        const pauseDuration = getBlockPauseDuration(textBlocks[blockIndex]);

        blockIndex++;

        blockIntervalRef.current = setTimeout(
          renderNextBlock,
          pauseDuration,
        ) as unknown as NodeJS.Timeout;
      } else {
        setIsRenderingBlocks(false);
        blockIntervalRef.current = null;
      }
    };

    // Start with first block immediately
    blockIntervalRef.current = setTimeout(
      renderNextBlock,
      300,
    ) as unknown as NodeJS.Timeout;
  };

  useEffect(() => {
    if (conversationId && user?.uid) {
      loadMessages();
    }
  }, [conversationId, user?.uid]);

  // Cleanup typing interval on unmount and conversation change
  useEffect(() => {
    return () => {
      if (typingIntervalRef.current) {
        clearTimeout(typingIntervalRef.current);
        typingIntervalRef.current = null;
      }
      if (blockIntervalRef.current) {
        clearTimeout(blockIntervalRef.current);
        blockIntervalRef.current = null;
      }
    };
  }, []);

  // Reset typing state when conversation changes
  useEffect(() => {
    if (typingIntervalRef.current) {
      clearTimeout(typingIntervalRef.current);
      typingIntervalRef.current = null;
    }
    if (blockIntervalRef.current) {
      clearTimeout(blockIntervalRef.current);
      blockIntervalRef.current = null;
    }
    setIsTyping(false);
    setTypingText("");
    setFullText("");
    setBlocks([]);
    setRenderedBlockCount(0);
    setIsRenderingBlocks(false);
  }, [conversationId]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [chatMessages, loading, isThinking, typingText, renderedBlockCount]);

  // Handle saving message to Firebase when typing or block rendering is complete
  useEffect(() => {
    if (
      !isTyping &&
      !isRenderingBlocks &&
      fullText &&
      conversationId &&
      user &&
      chatMessages.length > 0
    ) {
      const lastMessage = chatMessages[chatMessages.length - 1];
      if (lastMessage.role === "assistant" && lastMessage.content === "") {
        const saveMessage = async () => {
          try {
            // Update the last message with the full text
            setChatMessages((prev) => {
              const updated = [...prev];
              if (
                updated.length > 0 &&
                updated[updated.length - 1].role === "assistant"
              ) {
                updated[updated.length - 1].content = fullText;
              }
              return updated;
            });

            // Save to Firebase
            await MessagesService.addMessage(
              conversationId,
              user.uid,
              `assistant:${fullText}`,
            );

            // Reset states
            setTypingText("");
            setFullText("");
            setBlocks([]);
            setRenderedBlockCount(0);
          } catch (error) {
            console.error("Error saving message:", error);
          }
        };

        saveMessage();
      }
    }
  }, [
    isTyping,
    isRenderingBlocks,
    fullText,
    conversationId,
    user,
    chatMessages,
  ]);

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
        // Add assistant response immediately for images
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

        toast.success("Image g��nérée avec succès!");
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

        // Add placeholder message with empty content
        const assistantMsg: ChatMessage = {
          id: (Date.now() + 1).toString(),
          role: "assistant",
          content: "", // Will be filled by block rendering
          timestamp: Date.now(),
        };
        setChatMessages((prev) => [...prev, assistantMsg]);

        // Start block rendering with premium animation
        startBlockRendering(assistantContent);
      }

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
      setGeneratingImage(false);
    }
  };

  const addEmoji = (emoji: string) => {
    setMessage(message + emoji);
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
      className="flex-1 flex flex-col min-h-0 transition-colors duration-300"
      style={{
        backgroundColor: isDark ? "#0e0e0e" : "#F3F4F6",
      }}
    >
      {/* Main Content Area - Messages Container */}
      <div className="flex-1 overflow-y-auto flex flex-col px-6 md:px-8 py-6 animate-fadeIn min-h-0 items-center transition-colors duration-300">
        <div className="w-full max-w-2xl">
          {!conversationId ? (
            <div className="flex h-full items-center justify-center" style={{ paddingTop: "8%" }}>
              <div className="text-center">
                <div
                  className={`w-24 h-24 rounded-full mx-auto mb-8 flex items-center justify-center border-2 animate-scaleIn animate-haloPulse transition-all duration-300 ${
                    isDark ? "border-orange-400/30" : "border-orange-300/40"
                  }`}
                  style={{
                    backgroundImage:
                      "url(https://cdn.builder.io/api/v1/image/assets%2Fafa67d28f8874020a08a6dc1ed05801d%2F340d671f0c4b45db8b30096668d2bc7c)",
                    backgroundRepeat: "no-repeat",
                    backgroundPosition: "center",
                    backgroundSize: "cover",
                    boxShadow: isDark
                      ? "0 0 24px rgba(255, 200, 100, 0.15), inset 0 0 24px rgba(255, 200, 100, 0.05)"
                      : "0 0 20px rgba(255, 150, 80, 0.12), inset 0 0 20px rgba(255, 150, 80, 0.04)",
                  }}
                />
                <h2
                  className={`text-xl font-semibold mb-3 animate-slideUp transition-all duration-300 ${
                    isDark ? "text-foreground" : "text-[#1A1A1A]"
                  }`}
                  style={{
                    textShadow: isDark
                      ? "0 2px 8px rgba(0,0,0,0.3)"
                      : "0 1px 4px rgba(0,0,0,0.08)",
                  }}
                >
                  Sélectionnez une conversation
                </h2>
                <p
                  className={`text-sm animate-slideUp transition-all duration-300 ${
                    isDark ? "text-foreground/60" : "text-[#3F3F3F]/60"
                  }`}
                  style={{
                    animationDelay: "0.1s",
                    letterSpacing: "0.2px",
                  }}
                >
                  Cliquez sur une conversation à gauche pour commencer
                </p>
              </div>
            </div>
          ) : loadingMessages ? (
            <div className="flex h-full items-center justify-center">
              <Loader2
                className={`w-8 h-8 animate-spin transition-colors duration-300 ${
                  isDark ? "text-foreground/50" : "text-[#3F3F3F]/50"
                }`}
              />
            </div>
          ) : chatMessages.length === 0 ? (
            <div className="flex h-full items-center justify-center" style={{ paddingTop: "8%" }}>
              <div className="text-center">
                <div
                  className={`w-24 h-24 rounded-full mx-auto mb-8 flex items-center justify-center border-2 animate-scaleIn animate-haloPulse transition-all duration-300 ${
                    isDark ? "border-orange-400/30" : "border-orange-300/40"
                  }`}
                  style={{
                    backgroundImage:
                      "url(https://cdn.builder.io/api/v1/image/assets%2Fafa67d28f8874020a08a6dc1ed05801d%2F340d671f0c4b45db8b30096668d2bc7c)",
                    backgroundRepeat: "no-repeat",
                    backgroundPosition: "center",
                    backgroundSize: "cover",
                    boxShadow: isDark
                      ? "0 0 24px rgba(255, 200, 100, 0.15), inset 0 0 24px rgba(255, 200, 100, 0.05)"
                      : "0 0 20px rgba(255, 150, 80, 0.12), inset 0 0 20px rgba(255, 150, 80, 0.04)",
                  }}
                />
                <h2
                  className={`text-xl font-semibold mb-3 animate-slideUp transition-all duration-300 ${
                    isDark ? "text-foreground" : "text-[#1A1A1A]"
                  }`}
                  style={{
                    textShadow: isDark
                      ? "0 2px 8px rgba(0,0,0,0.3)"
                      : "0 1px 4px rgba(0,0,0,0.08)",
                  }}
                >
                  Commencez une conversation
                </h2>
                <p
                  className={`text-sm animate-slideUp transition-all duration-300 ${
                    isDark ? "text-foreground/60" : "text-[#3F3F3F]/60"
                  }`}
                  style={{
                    animationDelay: "0.1s",
                    letterSpacing: "0.2px",
                  }}
                >
                  Tapez un message ci-dessous pour commencer
                </p>
              </div>
            </div>
          ) : (
            <div className="space-y-3 pb-4">
              {chatMessages.map((msg, index) => {
                const isLastMessage = index === chatMessages.length - 1;
                const displayContent =
                  isLastMessage && isTyping ? typingText : msg.content;

                return (
                  <div
                    key={msg.id}
                    className={`flex w-full ${
                      msg.role === "user" ? "justify-end" : "justify-start"
                    } animate-messageFadeUp`}
                  >
                    {msg.role === "user" ? (
                      <div className="flex gap-2 items-start flex-row-reverse max-w-lg">
                        <div
                          className={`w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0 shadow-md overflow-hidden border transition-all duration-300 ${
                            isDark
                              ? "bg-gradient-to-br from-blue-500 to-blue-600 border-blue-400/50"
                              : "bg-gradient-to-br from-blue-400 to-blue-500 border-blue-300/50"
                          }`}
                        >
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
                          <div
                            className="rounded-lg rounded-tr-none py-2 px-3 text-sm break-words transition-all duration-300"
                            style={{
                              background: isDark
                                ? "linear-gradient(135deg, #1E40AF 0%, #1E3A8A 100%)"
                                : "linear-gradient(135deg, #2563EB 0%, #3B82F6 100%)",
                              color: "#FFFFFF",
                              height: "auto",
                              lineHeight: "1.3",
                              boxShadow: isDark
                                ? "0 4px 16px rgba(0, 0, 0, 0.3)"
                                : "0 3px 12px rgba(37, 99, 235, 0.25)",
                              backdropFilter: "blur(4px)",
                            }}
                          >
                            <MessageRenderer
                              content={msg.content}
                              role={msg.role}
                            />
                          </div>
                        </div>
                      </div>
                    ) : (
                      <div className="flex gap-2 items-start max-w-lg">
                        <div
                          className={`w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0 shadow-md border transition-all duration-300 ${
                            isDark
                              ? "bg-gradient-to-br from-orange-500 to-orange-600 border-orange-400/50"
                              : "bg-gradient-to-br from-orange-400 to-orange-500 border-orange-300/50"
                          }`}
                        >
                          <span className="text-xs font-bold text-white">
                            V
                          </span>
                        </div>
                        <div className="flex-1 max-w-md max-h-96 overflow-y-auto">
                          {isLastMessage &&
                          blocks.length > 0 &&
                          renderedBlockCount > 0 ? (
                            <div className="space-y-2.5">
                              {blocks
                                .slice(0, renderedBlockCount)
                                .map((block, blockIndex) => (
                                  <div
                                    key={blockIndex}
                                    className="rounded-lg rounded-tl-none py-2 px-3 text-sm break-words transition-all duration-300"
                                    style={{
                                      backgroundColor: isDark
                                        ? "#111418"
                                        : "#E5E7EB",
                                      color: isDark ? "#E5E7EB" : "#1E1E1E",
                                      height: "auto",
                                      lineHeight: "1.3",
                                      border: isDark
                                        ? "1px solid rgba(255, 255, 255, 0.08)"
                                        : "1px solid rgba(0, 0, 0, 0.06)",
                                      boxShadow: isDark
                                        ? "0 4px 16px rgba(0, 0, 0, 0.3)"
                                        : "0 2px 8px rgba(0, 0, 0, 0.08)",
                                      animation: `blockSlideUp 240ms cubic-bezier(0.34, 1.56, 0.64, 1) ${blockIndex * 50}ms both`,
                                    }}
                                  >
                                    <MessageRenderer
                                      content={block}
                                      role={msg.role}
                                    />
                                  </div>
                                ))}
                            </div>
                          ) : (
                            <div
                              className="rounded-lg rounded-tl-none py-2 px-3 text-sm break-words transition-all duration-300"
                              style={{
                                backgroundColor: isDark ? "#111418" : "#E5E7EB",
                                color: isDark ? "#E5E7EB" : "#1E1E1E",
                                height: "auto",
                                lineHeight: "1.3",
                                border: isDark
                                  ? "1px solid rgba(255, 255, 255, 0.08)"
                                  : "1px solid rgba(0, 0, 0, 0.06)",
                                boxShadow: isDark
                                  ? "0 4px 16px rgba(0, 0, 0, 0.3)"
                                  : "0 2px 8px rgba(0, 0, 0, 0.08)",
                              }}
                            >
                              <MessageRenderer
                                content={displayContent}
                                role={msg.role}
                              />
                            </div>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
              {(loading || isThinking || isTyping || isRenderingBlocks) && (
                <div className="flex w-full justify-start animate-springFade">
                  <div className="flex gap-2 items-start max-w-lg">
                    <div
                      className={`w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0 shadow-md border transition-all duration-300 ${
                        isDark
                          ? "bg-gradient-to-br from-orange-500 to-orange-600 border-orange-400/50"
                          : "bg-gradient-to-br from-orange-400 to-orange-500 border-orange-300/50"
                      }`}
                    >
                      <span className="text-xs font-bold text-white">V</span>
                    </div>
                    {isTyping || isRenderingBlocks ? (
                      <TypingIndicator />
                    ) : (
                      <ThinkingAnimation />
                    )}
                  </div>
                </div>
              )}
              <div ref={messagesEndRef} />
            </div>
          )}
        </div>
      </div>

      {/* Message Input Area - Fixed at Bottom */}
      <div
        className="w-full px-6 md:px-8 py-5 transition-colors duration-300"
        style={{
          backgroundColor: isDark ? "#0e0e0e" : "#F3F4F6",
          animation: "fadeIn 200ms ease-out",
        }}
      >
        <div className="flex flex-col items-center w-full">
          <div className="w-full max-w-2xl">
            {/* Chat Input Component */}
            <ChatInput
              message={message}
              onMessageChange={setMessage}
              onSend={handleSend}
              onAddEmoji={addEmoji}
              disabled={!conversationId}
              loading={loading}
              placeholder={
                conversationId
                  ? "Votre message..."
                  : "Sélectionnez une conversation..."
              }
            />

            {/* Image Generation Loading State */}
            {generatingImage && (
              <div
                className={`flex items-center gap-3 px-4 py-3 mt-3 rounded-lg animate-pulse transition-all duration-300 ${
                  isDark
                    ? "bg-gradient-to-r from-purple-600/20 to-purple-500/10 border border-purple-500/40"
                    : "bg-gradient-to-r from-purple-100/40 to-purple-50/40 border border-purple-300/40"
                }`}
              >
                <div className="flex gap-1">
                  <div
                    className={`w-2 h-2 rounded-full animate-bounce transition-colors duration-300 ${
                      isDark ? "bg-purple-400" : "bg-purple-500"
                    }`}
                    style={{ animationDelay: "0s" }}
                  />
                  <div
                    className={`w-2 h-2 rounded-full animate-bounce transition-colors duration-300 ${
                      isDark ? "bg-purple-400" : "bg-purple-500"
                    }`}
                    style={{ animationDelay: "0.2s" }}
                  />
                  <div
                    className={`w-2 h-2 rounded-full animate-bounce transition-colors duration-300 ${
                      isDark ? "bg-purple-400" : "bg-purple-500"
                    }`}
                    style={{ animationDelay: "0.4s" }}
                  />
                </div>
                <span
                  className={`text-sm font-medium transition-colors duration-300 ${
                    isDark ? "text-purple-300" : "text-purple-700"
                  }`}
                >
                  Génération d'image en cours...
                </span>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
