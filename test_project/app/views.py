# Deliberately vulnerable views
import requests

def get_data(url):
    # SSL verification disabled
    response = requests.get(url, verify=False)
    return response.json()

def render_comment(comment):
    # XSS via innerHTML
    return f"<div id='output'></div><script>document.getElementById('output').innerHTML = {comment}</script>"

debug = True
