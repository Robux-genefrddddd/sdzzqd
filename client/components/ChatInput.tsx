import { Send, Smile, Loader2 } from "lucide-react";
import { useState, useRef, useEffect } from "react";
import { useTheme } from "@/contexts/ThemeContext";
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
  "💯",
  "❤️",
  "✨",
  "🚀",
  "🤯",
];

const AUTO_RESIZE_CONFIG = {
  minHeight: 24,
  maxHeight: 120,
};

interface ChatInputProps {
  message: string;
  onMessageChange: (message: string) => void;
  onSend: () => void;
  onAddEmoji: (emoji: string) => void;
  disabled: boolean;
  loading: boolean;
  placeholder: string;
}

export function ChatInput({
  message,
  onMessageChange,
  onSend,
  onAddEmoji,
  disabled,
  loading,
  placeholder,
}: ChatInputProps) {
  const { isDark } = useTheme();
  const [emojiOpen, setEmojiOpen] = useState(false);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const handleTextareaAutoResize = () => {
    if (!textareaRef.current) return;
    textareaRef.current.style.height = `${AUTO_RESIZE_CONFIG.minHeight}px`;
    const scrollHeight = textareaRef.current.scrollHeight;
    const newHeight = Math.min(scrollHeight, AUTO_RESIZE_CONFIG.maxHeight);
    textareaRef.current.style.height = `${newHeight}px`;
  };

  const handleAddEmoji = (emoji: string) => {
    onAddEmoji(emoji);
    setEmojiOpen(false);
  };

  useEffect(() => {
    if (textareaRef.current) {
      handleTextareaAutoResize();
    }
  }, [message]);

  return (
    <div className="chat-input-container" style={{
      padding: "14px 18px",
      borderRadius: "16px",
      background: isDark 
        ? "rgba(255,255,255,0.04)" 
        : "rgba(255,255,255,0.6)",
      backdropFilter: "blur(8px)",
      border: isDark
        ? "1px solid rgba(255,255,255,0.08)"
        : "1px solid rgba(255,255,255,0.2)",
      boxShadow: isDark
        ? "0 4px 14px rgba(0,0,0,0.4)"
        : "0 2px 8px rgba(0,0,0,0.06)",
      transition: "all 200ms ease",
    }}>
      <div className="chat-input-inner flex items-center gap-3" style={{
        display: "flex",
        alignItems: "center",
        gap: "12px",
      }}>
        {/* Textarea */}
        <textarea
          ref={textareaRef}
          id="message-input"
          value={message}
          onChange={(e) => {
            onMessageChange(e.target.value);
            handleTextareaAutoResize();
          }}
          onKeyPress={(e) => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault();
              onSend();
            }
          }}
          disabled={disabled || loading}
          placeholder={placeholder}
          className="chat-textarea flex-1"
          style={{
            flex: 1,
            display: "flex",
            alignItems: "center",
            fontSize: "15.5px",
            lineHeight: "1.4",
            color: isDark ? "#FFFFFF" : "#1A1A1A",
            backgroundColor: "transparent",
            border: "none",
            outline: "none",
            padding: "0",
            margin: "0",
            height: "auto",
            minHeight: "24px",
            maxHeight: "120px",
            overflow: "hidden",
            resize: "none",
            fontFamily: "Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
          }}
        />

        {/* Emoji Button */}
        <Popover open={emojiOpen} onOpenChange={setEmojiOpen}>
          <PopoverTrigger asChild>
            <button
              className="emoji-button flex-shrink-0"
              style={{
                width: "28px",
                height: "28px",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                borderRadius: "50%",
                border: "none",
                background: isDark
                  ? "rgba(255,255,255,0.08)"
                  : "rgba(0,0,0,0.05)",
                color: isDark ? "#FFFFFF" : "#1A1A1A",
                cursor: "pointer",
                transition: "0.15s ease",
                flexShrink: 0,
              }}
              onMouseEnter={(e) => {
                const target = e.currentTarget as HTMLButtonElement;
                target.style.background = isDark
                  ? "rgba(255,255,255,0.12)"
                  : "rgba(0,0,0,0.09)";
                target.style.transform = "scale(1.05)";
              }}
              onMouseLeave={(e) => {
                const target = e.currentTarget as HTMLButtonElement;
                target.style.background = isDark
                  ? "rgba(255,255,255,0.08)"
                  : "rgba(0,0,0,0.05)";
                target.style.transform = "scale(1)";
              }}
              onMouseDown={(e) => {
                const target = e.currentTarget as HTMLButtonElement;
                target.style.transform = "scale(0.82)";
              }}
              onMouseUp={(e) => {
                const target = e.currentTarget as HTMLButtonElement;
                target.style.transform = "scale(1)";
              }}
              aria-label="Ajouter un emoji"
            >
              <Smile size={18} strokeWidth={1.5} />
            </button>
          </PopoverTrigger>
          <PopoverContent
            className={`w-64 p-3 border rounded-2xl shadow-xl transition-colors duration-300 ${
              isDark
                ? "bg-card border-white/20"
                : "bg-[#FFFFFF] border-black/[0.08]"
            }`}
          >
            <div className="grid grid-cols-5 gap-2">
              {EMOJIS.map((emoji) => (
                <button
                  key={emoji}
                  onClick={() => handleAddEmoji(emoji)}
                  className={`p-2 rounded-lg transition-all duration-200 text-xl hover:scale-125 transform ${
                    isDark
                      ? "hover:bg-white/10"
                      : "hover:bg-black/[0.05]"
                  }`}
                >
                  {emoji}
                </button>
              ))}
            </div>
          </PopoverContent>
        </Popover>

        {/* Send Button */}
        <button
          onClick={onSend}
          disabled={loading || !message.trim() || disabled}
          className="send-button flex-shrink-0"
          style={{
            width: "28px",
            height: "28px",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            borderRadius: "50%",
            border: "none",
            background: message.trim() && !disabled
              ? isDark
                ? "rgba(59, 130, 246, 0.1)"
                : "rgba(59, 130, 246, 0.08)"
              : "transparent",
            color: message.trim() && !disabled
              ? "#3b82f6"
              : isDark
                ? "rgba(255, 255, 255, 0.3)"
                : "rgba(0, 0, 0, 0.2)",
            cursor: message.trim() && !disabled ? "pointer" : "default",
            transition: "0.15s ease",
            flexShrink: 0,
          }}
          onMouseEnter={(e) => {
            const target = e.currentTarget as HTMLButtonElement;
            if (message.trim() && !disabled) {
              target.style.background = isDark
                ? "rgba(59, 130, 246, 0.15)"
                : "rgba(59, 130, 246, 0.12)";
              target.style.transform = "scale(1.05)";
            }
          }}
          onMouseLeave={(e) => {
            const target = e.currentTarget as HTMLButtonElement;
            if (message.trim() && !disabled) {
              target.style.background = isDark
                ? "rgba(59, 130, 246, 0.1)"
                : "rgba(59, 130, 246, 0.08)";
              target.style.transform = "scale(1)";
            }
          }}
          onMouseDown={(e) => {
            const target = e.currentTarget as HTMLButtonElement;
            if (message.trim() && !disabled) {
              target.style.transform = "scale(0.82)";
            }
          }}
          onMouseUp={(e) => {
            const target = e.currentTarget as HTMLButtonElement;
            if (message.trim() && !disabled) {
              target.style.transform = "scale(1)";
            }
          }}
          aria-label="Envoyer le message"
        >
          {loading ? (
            <Loader2 size={16} className="animate-spin" strokeWidth={2} />
          ) : (
            <Send size={16} strokeWidth={2} />
          )}
        </button>
      </div>
    </div>
  );
}
