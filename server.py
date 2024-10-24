from flask import Flask, request, redirect, session, make_response
import base64
import os
import xml.etree.ElementTree as ET
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from onelogin.saml2.response import OneLogin_Saml2_Response

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
    """Create and sign a simple SAML response."""
    saml_response = '''
    <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="_a0fce21042cb92e70a8c" IssueInstant="2024-10-24T16:44:05Z" Destination="http://192.168.29.178:5000/saml/acs">
        <saml:Issuer>http://192.168.29.178:5001/metadata/</saml:Issuer>
        <samlp:Status>
            <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
        </samlp:Status>
        <saml:Assertion Version="2.0" ID="_d287356a3f769f" IssueInstant="2024-10-24T16:44:05Z">
            <saml:Issuer>http://192.168.29.178:5001/metadata/</saml:Issuer>
            <saml:Subject>
                <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">user@example.com</saml:NameID>
            </saml:Subject>

            <!-- Add the Conditions element here -->
            <saml:Conditions NotBefore="2024-10-23T11:44:05Z" NotOnOrAfter="2024-10-23T12:44:05Z">
                <saml:AudienceRestriction>
                    <saml:Audience>http://192.168.29.178:5000/metadata/</saml:Audience>
                </saml:AudienceRestriction>
            </saml:Conditions>

            <saml:AttributeStatement>
                <saml:Attribute Name="name">
                    <saml:AttributeValue>Test User</saml:AttributeValue>
                </saml:Attribute>
            </saml:AttributeStatement>
        </saml:Assertion>
    </samlp:Response>
    '''

    # Path to your private key and certificate
    private_key = open(os.path.join(app.root_path, 'saml_server', 'saml_certs', 'saml.key')).read()
    cert = open(os.path.join(app.root_path, 'saml_server', 'saml_certs', 'saml.crt')).read()

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
        <form action="http://192.168.29.178:5000/saml/acs" method="POST">
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

if __name__ == "__main__":
    app.run(port=5001, debug=True, host="0.0.0.0")
