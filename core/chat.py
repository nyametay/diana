import os
from google import genai
from google.genai import types
from google.genai.types import GenerateContentConfig


def generate(input_text: str, summary: str = "", context=None):
    """
    Generates DIANA responses using Gemini.
    Includes:
    - System prompt
    - Session summary
    - Recent context messages
    - User message
    """

    client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))
    model = "gemini-3-pro-preview"

    if context is None:
        context = []

    # -----------------------------
    # BUILD CONTEXT BLOCK
    # -----------------------------
    context_block = ""

    if summary:
        context_block += f"--- Summary of previous conversation ---\n{summary}\n\n"

    if context:
        context_block += "--- Recent messages ---\n"
        for c in context:
            context_block += f"User: {c['message']}\nAssistant: {c['response']}\n"
        context_block += "\n"

    # -----------------------------
    # BUILD SYSTEM PROMPT
    # -----------------------------
    system_instruction = types.Part.from_text(text="""
You are DIANA — a calm, neutral, structured ethical reasoning assistant.

PRIMARY ROLE:
Help users explore ethical dilemmas by offering structured ethical frameworks and
reflective insights. DO NOT provide commands, moral judgments, or legal/medical advice.

ETHICAL FRAMEWORKS TO USE:
- Utilitarianism
- Deontology
- Virtue Ethics
(Optional when relevant: Care Ethics, Justice/Fairness)

FLOW FORMAT:
1. Understanding
2. Framework analyses
3. Balanced interpretation
4. Reflective closing question

TONE:
Warm, calm, neutral, supportive.
Simple and clear language only.
""")

    # -----------------------------
    # USER MESSAGE
    # -----------------------------
    user_message = types.Content(
        role="user",
        parts=[types.Part.from_text(text=context_block + input_text)]
    )

    # -----------------------------
    # CONFIG
    # -----------------------------
    config = GenerateContentConfig(
        system_instruction=[system_instruction],
        tools=[],
        thinking_config=types.ThinkingConfig(thinking_level="HIGH"),
        temperature=0.7,
        max_output_tokens=800
    )

    # -----------------------------
    # EXECUTE (STREAMING)
    # -----------------------------
    final_text = ""

    for chunk in client.models.generate_content_stream(
        model=model,
        contents=[user_message],
        config=config
    ):
        if chunk.text:
            final_text += chunk.text

    return final_text.strip()


def summarize_chat(history):
    """
    Summarizes a full session into a short memory block using Gemini.
    Triggered every X messages.
    """
    if not history:
        return ""

    client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))
    model = "gemini-3-pro-preview"

    # Build transcript
    transcript = ""
    for h in history:
        transcript += f"User: {h.message}\nAssistant: {h.response}\n"

    system_prompt = """
You are DIANA's memory engine.

Summarize the entire conversation into a compact, neutral, ethically-relevant
memory block. DO NOT include sensitive personal details unless explicitly necessary.

The summary must:
- Capture ongoing dilemmas, themes, and unresolved tensions
- Capture user preferences, moral concerns, or repeated patterns
- Be concise (10–40 lines)
- NOT include direct quotes
- Be suitable as context for future ethical reasoning
"""

    contents = [
        types.Content(role="user", parts=[types.Part.from_text(text=transcript)])
    ]

    config = GenerateContentConfig(
        system_instruction=[types.Part.from_text(text=system_prompt)],
        temperature=0.3
    )

    response = client.models.generate_content(
        model=model,
        contents=contents,
        config=config
    )

    return response.text.strip()
