# sources.json — forward validation config

Build **sources.json** for forward validation: keep only traces that start from **web entrypoints** (routes, handlers, API). Use tools to explore the repo; submit the config **only** via the `submit_sources_config` tool — do not output JSON in chat.

## Purpose

Forward validation filters traces so that only sources reachable from the web (routes, handlers, API endpoints) are accepted. This reduces noise and keeps only web-accessible traces.

## Fields (all optional; at least one block recommended for precision)

- **file_patterns** (array): Each element `{ "pattern": "**/routes.py", "language": "python" }`. Glob path (supports `**/`). Optional `language`. A source is valid if its file matches a pattern.
- **function_patterns** (array of strings): Regex on full function name (including module), e.g. `".*_endpoint"`, `"handle_.*"`.
- **function_names** (array of strings): Exact function names or suffixes (e.g. `module.func`).
- **source_indicators** (array of strings): Substrings that must appear in code. Used when file/function patterns are not set.
- **language_specific** (object): Keys = language (python, javascript, …). Value = `{ "patterns": ["@app\\.route", "register_endpoint"] }` — regex patterns on code.

## Logic

If both file_patterns and function_patterns/function_names are set: a source is valid if it matches **either** a file pattern **or** a function pattern (OR). Recommend setting at least file_patterns or function_* for precise validation.

## Example (file patterns only)

```json
{
  "file_patterns": [
    { "pattern": "**/routes.py", "language": "python" },
    { "pattern": "**/app.py", "language": "python" }
  ]
}
```

## Example (function patterns only)

```json
{
  "function_patterns": [".*_endpoint", "handle_.*"],
  "function_names": ["register_route", "api_handler"]
}
```

## Example (combined)

```json
{
  "file_patterns": [
    { "pattern": "**/routes.py", "language": "python" }
  ],
  "function_patterns": [".*_endpoint"],
  "source_indicators": ["POST", "GET", "@app.route"],
  "language_specific": {
    "python": { "patterns": ["@app\\.route", "register_endpoint"] }
  }
}
```

**You must call the `submit_sources_config` tool with the config fields as arguments to submit the final sources.json. Do not paste JSON in your message.**
