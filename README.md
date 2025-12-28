```
pip install -r requirements.txt
python3 auditor.py --repo ./fastapi/ --out ./out/
```

```
python3 all.py --config config.json [--enable-js] [--debug]
```

# Download repos to 'repos' folder and analyze them
python3 all.py --config config.json

# Use custom repos directory
python3 all.py --config config.json --repos-dir my_repos

# Skip download if repos already exist
python3 all.py --config config.json --skip-download

# Download only 5 repos
python3 all.py --config config.json --repo-count 5


Config file 
{
    "base_url": "https://llm.api.cloud.yandex.net/v1",
    "api_key": "your-api-key",
    "model": "yandexgpt",
    "max_concurrent": 5
}
