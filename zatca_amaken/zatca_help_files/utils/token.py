import base64

def get_authHeader(username, password):
    token = f'{username}:{password}'
    return f"Basic {base64.b64encode(token.encode()).decode()}"