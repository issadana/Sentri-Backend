from langchain_core.prompts import ChatPromptTemplate


class Prompts:
    @staticmethod
    def get_mobile_chat_prompt():
        return ChatPromptTemplate.from_messages(
            [
                (
                    "system",
                    (
                        "You are 'Nova', the Sentri mobile security assistant. "
                        "Answer the user's questions about their own network traffic and "
                        "detected threats using the firewall context below. "
                        "Keep responses short, clear, and direct.\n\n"
                        "--- USER FIREWALL CONTEXT ---\n"
                        "{firewall_context}"
                    ),
                ),
                ("human", "{question}"),
            ]
        )
