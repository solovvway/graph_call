#!/usr/bin/env python3

from __future__ import annotations

import json

import pydantic

from yandex_cloud_ml_sdk import YCloudML

text = """
Name any three groups of grocery store products. 
For each group, give three subgroups. 
Present the result in JSON format.
"""


def main() -> None:
    sdk = YCloudML(
        folder_id="",
        auth="",
    )

    model = sdk.models.completions("gpt-oss-120b")

    model = model.configure(response_format="json")
    result = model.run(
        [
            {"role": "user", "text": text},
        ]
    )
    print("JSON result:", result[0].text)


if __name__ == "__main__":
    main()
