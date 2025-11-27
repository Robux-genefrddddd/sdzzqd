export interface AIConfig {
  model: string;
  systemPrompt: string;
  temperature: number;
  maxTokens: number;
}

const DEFAULT_CONFIG: AIConfig = {
  model: "x-ai/grok-4.1-fast:free",
  systemPrompt: "Tu es un assistant utile et amical. Réponds en français.",
  temperature: 0.7,
  maxTokens: 2048,
};

export class AIService {
  static async getConfig(): Promise<AIConfig> {
    try {
      const response = await fetch("/api/ai/config");
      if (!response.ok) {
        console.debug("Failed to fetch AI config, using default");
        return DEFAULT_CONFIG;
      }
      return await response.json();
    } catch (error) {
      console.debug("Error fetching AI config, using default:", error);
      return DEFAULT_CONFIG;
    }
  }

  static async updateConfig(config: Partial<AIConfig>): Promise<void> {
    try {
      const response = await fetch("/api/ai/config", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(config),
      });

      if (!response.ok) {
        throw new Error("Failed to update AI config");
      }
    } catch (error) {
      throw new Error("Erreur lors de la mise à jour de la configuration IA");
    }
  }

  static async sendMessage(
    userMessage: string,
    conversationHistory: Array<{ role: string; content: string }> = [],
  ): Promise<string> {
    const config = await this.getConfig();

    try {
      const response = await fetch("/api/ai/chat", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          userMessage,
          conversationHistory,
          model: config.model,
          temperature: config.temperature,
          maxTokens: config.maxTokens,
          systemPrompt: config.systemPrompt,
        }),
      });

      // Try to parse response body as text first, then JSON
      let responseText: string;
      try {
        responseText = await response.text();
      } catch (error) {
        console.error("Failed to read response:", error);
        throw new Error("Erreur serveur: impossible de lire la réponse");
      }

      let data: any;
      try {
        data = JSON.parse(responseText);
      } catch (parseError) {
        console.error("Failed to parse response JSON:", parseError);
        console.error("Response was:", responseText.substring(0, 500));
        throw new Error(
          `Erreur serveur: réponse invalide (${responseText.substring(0, 50)}...)`,
        );
      }

      if (!response.ok) {
        const errorMessage = data?.error || `API error: ${response.status}`;
        throw new Error(errorMessage);
      }

      return data.content || "Pas de réponse";
    } catch (error) {
      throw error instanceof Error
        ? error
        : new Error("Erreur lors de la requête IA");
    }
  }

  static getAvailableModels(): string[] {
    return [
      "openrouter/auto",
      "gpt-4-turbo-preview",
      "gpt-3.5-turbo",
      "claude-3-opus",
      "claude-3-sonnet",
      "mistral-large",
    ];
  }
}
