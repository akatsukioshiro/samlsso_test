from flask import Flask, request, redirect, session, make_response
import base64
import os
import xml.etree.ElementTree as ET
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from onelogin.saml2.response import OneLogin_Saml2_Response
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = 'another_secret_key'

def sign_saml_response(saml_response_xml, private_key, cert):
    """Sign the SAML response."""
    signed_saml_response = OneLogin_Saml2_Utils.add_sign(
        saml_response_xml,  # Raw XML, not base64 encoded
        private_key,
        cert
    )
    return signed_saml_response

def generate_saml_response():
    """Create and sign a simple SAML response with dynamic timestamps."""
    
    # Get the current UTC time
    current_time = datetime.utcnow()

    # Set User
    auth_user = "Ashish Nair"

    # Set dynamic times for the response
    issue_instant = current_time.strftime('%Y-%m-%dT%H:%M:%SZ')  # Current time
    not_before = (current_time - timedelta(minutes=5)).strftime('%Y-%m-%dT%H:%M:%SZ')  # 5 minutes ago
    not_on_or_after = (current_time + timedelta(minutes=1)).strftime('%Y-%m-%dT%H:%M:%SZ')  # 2 hours in the future
    authn_instant = current_time.strftime('%Y-%m-%dT%H:%M:%SZ')  # Current time for authentication instant

    # Create the SAML response with dynamic values
    saml_response = f'''
    <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="_a0fce21042cb92e70a8c" IssueInstant="{issue_instant}" Destination="http://localhost:5000/saml/acs">
        <saml:Issuer>http://localhost:5001/metadata/</saml:Issuer>
        <samlp:Status>
            <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
        </samlp:Status>
        <saml:Assertion Version="2.0" ID="_d287356a3f769f" IssueInstant="{issue_instant}">
            <saml:Issuer>http://localhost:5001/metadata/</saml:Issuer>
            <saml:Subject>
                <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">user@example.com</saml:NameID>
                
                <!-- Add the SubjectConfirmation element here -->
                <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                    <saml:SubjectConfirmationData NotOnOrAfter="{not_on_or_after}"
                                                  Recipient="http://localhost:5000/saml/acs"
                                                  InResponseTo="_a0fce21042cb92e70a8c"/>
                </saml:SubjectConfirmation>
            </saml:Subject>

            <!-- Add the Conditions element here -->
            <saml:Conditions NotBefore="{not_before}" NotOnOrAfter="{not_on_or_after}">
                <saml:AudienceRestriction>
                    <saml:Audience>http://localhost:5000/metadata/</saml:Audience>
                </saml:AudienceRestriction>
            </saml:Conditions>

            <!-- Add the AuthnStatement element here -->
            <saml:AuthnStatement AuthnInstant="{authn_instant}" SessionIndex="_abc123">
                <saml:AuthnContext>
                    <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
                </saml:AuthnContext>
            </saml:AuthnStatement>

            <saml:AttributeStatement>
                <saml:Attribute Name="name">
                    <saml:AttributeValue>{auth_user}</saml:AttributeValue>
                </saml:Attribute>
            </saml:AttributeStatement>
        </saml:Assertion>
    </samlp:Response>
    '''

    # Path to your private key and certificate
    private_key = open(os.path.join(app.root_path, 'saml_idp', 'saml_certs', 'saml.key')).read()
    cert = open(os.path.join(app.root_path, 'saml_idp', 'saml_certs', 'saml.crt')).read()

    # Sign the SAML response (pass raw XML, not base64 encoded)
    signed_response = sign_saml_response(saml_response, private_key, cert)

    # Now base64 encode the signed response
    saml_response_encoded = base64.b64encode(signed_response).decode('utf-8')

    return saml_response_encoded

@app.route('/')
def index():
    if 'samlUserdata' in session:
        return f"Hello {session['samlUserdata']}! <a href='/logout'>Logout</a>"
    else:
        return 'Identity Provider ready. <a href="/login">Login</a>'

@app.route('/login')
def login():
    # Simulate IdP login (In reality, you'd have some login flow here)
    return redirect('/saml_response')

@app.route('/saml_response')
def saml_response():
    # Generate a SAML response and redirect to the SP's ACS endpoint
    saml_response = generate_saml_response()
    relay_state = request.args.get('RelayState', '/')
    
    html_response = f'''
    <html>
    <body onload="document.forms[0].submit()">
        <form action="http://localhost:5000/saml/acs" method="POST">
            <input type="hidden" name="SAMLResponse" value="{saml_response}"/>
            <input type="hidden" name="RelayState" value="{relay_state}"/>
            <noscript><input type="submit" value="Submit"></noscript>
        </form>
    </body>
    </html>
    '''
    
    return html_response

@app.route('/logout')
def logout():
    session.pop('samlUserdata', None)
    return redirect('/')

@app.route('/favicon.ico')
def favicon():
    return make_response('', 204)  # No content

if __name__ == "__main__":
    app.run(port=5001, debug=True)
