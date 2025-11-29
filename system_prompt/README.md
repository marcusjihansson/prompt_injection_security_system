# System Prompt

This directory contains the system prompt configuration used in demos and testing.

## Structure

- `system_prompt.json`: JSON file containing the system prompt text.

## Format

The JSON file should have the following structure:

```json
{
  "system_prompt": "Your system prompt text here..."
}
```

## Usage

The demo script (`demo.py`) loads this system prompt by default. You can customize it by editing `system_prompt.json` or setting the `SYSTEM_PROMPT_PATH` environment variable to point to a different JSON file.

Example custom prompt:

```json
{
  "system_prompt": "You are a helpful AI assistant focused on threat detection and security analysis."
}
```

## Customization

- Modify the `system_prompt` value to change the AI's behavior in demos.
- Ensure the prompt aligns with the threat detection context for accurate testing.
