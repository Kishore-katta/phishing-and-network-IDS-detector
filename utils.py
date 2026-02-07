
def tokenizer_url(url):
    """Split URL by forward slash to separate domain and path components."""
    if not isinstance(url, str):
        url = str(url)
    return url.split('/')
