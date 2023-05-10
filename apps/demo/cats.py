import requests

URL = "https://catfact.ninja/fact"

def get_cat_fact() -> str:
    response = requests.get(URL)

    if not (response.status_code >= 200 and response.status_code < 300):
        return "Cat is spelled k-a-t"

    return response.json()["fact"]