from flask import Flask, redirect, request, session, url_for
from onelogin.saml2.auth import OneLogin_Saml2_Auth
import os
import json
import base64

app = Flask(__name__)
app.secret_key = 'your_secret_key'

def init_saml_auth(req):
    saml_settings_path = os.path.join(app.root_path, 'saml_client')

    with open(os.path.join(saml_settings_path, 'settings.json')) as f:
        settings = json.load(f)  # Properly load the settings as a dictionary
        print("Loaded settings: ", settings)  # Debug print

    auth = OneLogin_Saml2_Auth(req, custom_base_path=saml_settings_path)
    return auth

def prepare_flask_request(request):
    url_data = request.url
    return {
        'https': 'on' if request.scheme == 'https' else 'off',
        'http_host': request.host,
        'server_port': request.environ.get('SERVER_PORT'),
        'script_name': request.environ.get('PATH_INFO'),
        'get_data': request.args.copy(),
        'post_data': request.form.copy()
    }

@app.route('/')
def index():
    if 'samlUserdata' in session:
        return f"Hello {session['samlUserdata']['name']}! <a href='/logout'>Logout</a>"
    else:
        return 'Hello, please <a href="/login">login</a>.'

@app.route('/login')
def login():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    return redirect(auth.login())

@app.route('/saml/acs', methods=['POST'])
def saml_acs():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)

    # Print the received SAML response for debugging
    saml_response = request.form.get('SAMLResponse')
    print("SAMLResponse received:", base64.b64decode(saml_response).decode('utf-8'))

    auth.process_response()
    errors = auth.get_errors()
    if not errors:
        session['samlUserdata'] = auth.get_attributes()
        return redirect('/')
    else:
        print("SAML Authentication Errors:", errors)  # Debug print the errors
        print("Last Error Reason:", auth.get_last_error_reason())  # Important for debugging
        return 'SAML Authentication failed', 400

@app.route('/logout')
def logout():
    session.pop('samlUserdata', None)
    return redirect('/')

if __name__ == "__main__":
    app.run(port=5000, debug=True, host="0.0.0.0")