try:
    import openai
    print("openai found")
except ImportError:
    print("openai not found")

try:
    import tree_sitter_languages
    print("tree_sitter_languages found")
except ImportError:
    print("tree_sitter_languages not found")