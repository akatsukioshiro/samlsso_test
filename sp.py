from flask import Flask, redirect, request, session, url_for, make_response
from onelogin.saml2.auth import OneLogin_Saml2_Auth
import os
import json
import base64
import xml.etree.ElementTree as ET
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key'

def init_saml_auth(req):
    saml_settings_path = os.path.join(app.root_path, 'saml_sp')

    with open(os.path.join(saml_settings_path, 'settings.json')) as f:
        settings = json.load(f)
        print("Loaded settings: ", settings)

    auth = OneLogin_Saml2_Auth(req, custom_base_path=saml_settings_path)
    return auth

def prepare_flask_request(request):
    return {
        'https': 'on' if request.scheme == 'https' else 'off',
        'http_host': request.host,
        'server_port': request.environ.get('SERVER_PORT'),
        'script_name': request.environ.get('PATH_INFO'),
        'get_data': request.args.copy(),
        'post_data': request.form.copy()
    }

def get_saml_times(assertion):
    """Extract NotBefore and NotOnOrAfter from the SAML assertion."""
    try:
        root = ET.fromstring(assertion)
        # Find the Conditions element in the assertion
        conditions = root.find('.//{urn:oasis:names:tc:SAML:2.0:assertion}Conditions')
        if conditions is not None:
            not_before = conditions.attrib.get('NotBefore')
            not_on_or_after = conditions.attrib.get('NotOnOrAfter')
            return not_before, not_on_or_after
        else:
            print("Conditions element not found in the assertion")
            return None, None
    except Exception as e:
        print(f"Error parsing SAML assertion: {e}")
        return None, None

def get_current_time(assertion):
    """Extract AuthnInstant from the SAML assertion."""
    try:
        root = ET.fromstring(assertion)
        # Find the AuthnStatement element in the assertion
        statement = root.find('.//{urn:oasis:names:tc:SAML:2.0:assertion}AuthnStatement')
        if statement is not None:
            auth_instant = statement.attrib.get('AuthnInstant')
            return auth_instant
        else:
            print("AuthnStatement element not found in the assertion")
            return None
    except Exception as e:
        print(f"Error parsing SAML assertion: {e}")
        return None

def is_session_valid(not_on_or_after):
    """Check if the current time is before the NotOnOrAfter time."""
    current_time = datetime.utcnow()
    session_end_time = datetime.strptime(not_on_or_after, "%Y-%m-%dT%H:%M:%SZ")
    return current_time < session_end_time

@app.route('/')
def index():
    if 'samlUserdata' in session:
        ct = datetime.utcnow()
        ct = ct.strftime("%d %B %Y %H:%M:%S UTC")
        assertion = session.get('samlAssertion', '')
        not_before, not_on_or_after = get_saml_times(assertion)

        # Check if the session is still valid
        if not is_session_valid(not_on_or_after):
            return redirect(url_for('logout'))  # Automatically log out if session expired
        

        auth_instant = get_current_time(assertion)
        auth_instant = datetime.strptime(auth_instant, "%Y-%m-%dT%H:%M:%SZ").strftime("%d %B %Y %H:%M:%S UTC")
        not_before = datetime.strptime(not_before, "%Y-%m-%dT%H:%M:%SZ").strftime("%d %B %Y %H:%M:%S UTC")
        not_on_or_after = datetime.strptime(not_on_or_after, "%Y-%m-%dT%H:%M:%SZ").strftime("%d %B %Y %H:%M:%S UTC")
        
        return f"""
    <html>
    <head>
        <script type="text/javascript">
            // Function to update the session data asynchronously
            async function updateSession() {{
                try {{
                    // Fetch the session data from the server
                    const response = await fetch('/session-status');
                    const data = await response.json();

                    // Update the HTML content with the latest session data
                    document.getElementById('currentTime').innerHTML = data.current_time;
                    document.getElementById('authInstant').innerHTML = data.auth_instant;
                    document.getElementById('notBefore').innerHTML = data.not_before;
                    document.getElementById('notOnOrAfter').innerHTML = data.not_on_or_after;

                    // If session is no longer valid, redirect to the logout page
                    if (!data.session_valid) {{
                        window.location.href = '/logout';
                    }}
                }} catch (error) {{
                    console.error('Error fetching session data:', error);
                }}
            }}

            // Call the update function every 2 seconds
            setInterval(updateSession, 2000);
        </script>
    </head>
    <body>
        <p>Hello {session['samlUserdata']['name']}!</p>
        <p>Current Time: <span id="currentTime">{ct}</span></p>
        <p>Session started at <span id="authInstant">{auth_instant}</span> and Session is Valid!</p>
        <p>From: <span id="notBefore">{not_before}</span></p>
        <p>To: <span id="notOnOrAfter">{not_on_or_after}</span></p>
        <a href='/logout'>Logout</a>
    </body>
    </html>
"""
    else:
        return 'Hello, please <a href="/login">login</a>.'

@app.route('/session-status')
def session_status():
    if 'samlUserdata' in session:
        ct = datetime.utcnow()
        current_time = ct.strftime("%d %B %Y %H:%M:%S UTC")
        
        assertion = session.get('samlAssertion', '')
        not_before, not_on_or_after = get_saml_times(assertion)

        # Check if the session is still valid
        session_valid = is_session_valid(not_on_or_after)

        # Parse and format times
        auth_instant = get_current_time(assertion)
        auth_instant_formatted = datetime.strptime(auth_instant, "%Y-%m-%dT%H:%M:%SZ").strftime("%d %B %Y %H:%M:%S UTC")
        not_before_formatted = datetime.strptime(not_before, "%Y-%m-%dT%H:%M:%SZ").strftime("%d %B %Y %H:%M:%S UTC")
        not_on_or_after_formatted = datetime.strptime(not_on_or_after, "%Y-%m-%dT%H:%M:%SZ").strftime("%d %B %Y %H:%M:%S UTC")

        # Return the data as JSON for the client-side JavaScript
        return {
            'current_time': current_time,
            'auth_instant': auth_instant_formatted,
            'not_before': not_before_formatted,
            'not_on_or_after': not_on_or_after_formatted,
            'session_valid': session_valid
        }
    else:
        return {'error': 'No session found'}, 401

@app.route('/favicon.ico')
def favicon():
    return make_response('', 204)  # No content

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
    decode_response = base64.b64decode(saml_response).decode('utf-8')
    print("SAMLResponse received:", decode_response)

    auth.process_response()
    errors = auth.get_errors()

    if not errors:
        session['samlUserdata'] = auth.get_attributes()

        assertion = extract_assertion_from_response(decode_response)
        session['samlAssertion'] = assertion  # Save the assertion for later use
        
        return redirect('/')
    else:
        print("SAML Authentication Errors:", errors)
        print("Last Error Reason:", auth.get_last_error_reason())
        return 'SAML Authentication failed', 400

def extract_assertion_from_response(response_xml):
    """Extract the Assertion part of the SAML response."""
    try:
        root = ET.fromstring(response_xml)
        assertion = root.find('.//{urn:oasis:names:tc:SAML:2.0:assertion}Assertion')
        if assertion is not None:
            return ET.tostring(assertion, encoding='unicode')
        else:
            return None
    except Exception as e:
        print(f"Error extracting assertion: {e}")
        return None

@app.route('/logout')
def logout():
    session.pop('samlUserdata', None)
    session.pop('samlAssertion', None)
    return redirect('/')

if __name__ == "__main__":
    app.run(port=5000, debug=True)
