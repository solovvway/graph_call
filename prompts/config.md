# Config for LLM-SAST scanner

Build a JSON config for the SAST scanner (llm_aditor). Use tools to explore the repo; submit the config **only** via the `submit_config` tool — do not output JSON in chat.

## Fields

**Required:**
- `repos_path` (string): path to directory containing repos (must exist)
- `base_url` (string): LLM API base URL
- `api_key` (string): LLM API key

**Optional:**
- `reports_dir` (string): output dir for reports (default: "reports")
- `folder_id` (string): Yandex Cloud folder ID
- `model` (string): model name (default: "yandexgpt-lite")
- `debug` (boolean): enable debug
- `enable_js` (boolean): analyze JS/TS
- `temperature` (number): 0–2
- `streams` or `max_concurrent` (integer): parallel requests, > 0
- `save_no_vuln_traces` (boolean): save traces with no vulnerability
- `prompt_path` (string): path to prompt file for LLM (e.g. prompts/prompt.md)

**Optional for precision:**
- `exclude_dirs` (array of strings): dir names to skip
- `include_extensions` (array of strings): e.g. [".py", ".js"] — use get_languages to see allowed
- `max_file_size_kb` (integer): skip larger files
- `sources_config_path` (string): path to sources.json for core4

## Example (minimal)

```json
{
  "repos_path": "./repos",
  "base_url": "https://llm.example/v1",
  "api_key": "sk-..."
}
```

## Example (extended)

```json
{
  "repos_path": "./repos",
  "reports_dir": "reports",
  "base_url": "https://llm.example/v1",
  "api_key": "sk-...",
  "folder_id": "b1g...",
  "model": "yandexgpt-lite",
  "enable_js": true,
  "temperature": 0.0,
  "max_concurrent": 8,
  "save_no_vuln_traces": false,
  "prompt_path": "prompts/prompt.md",
  "exclude_dirs": ["node_modules", ".git"],
  "include_extensions": [".py", ".js", ".ts"]
}
```

**You must call the `submit_config` tool with the config fields as arguments to submit the final config. Do not paste JSON in your message.**
