import os

from flask import (Flask, request, render_template, redirect, session,
                   make_response)

from urllib.parse import urlparse

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils

from flask import jsonify
from flask_cors import CORS


app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = 'onelogindemopytoolkit9'
app.config['SAML_PATH'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'saml')



def init_saml_auth(req):
    auth = OneLogin_Saml2_Auth(req, custom_base_path=app.config['SAML_PATH'])
    return auth


def prepare_flask_request(request):
    # If server is behind proxys or balancers use the HTTP_X_FORWARDED fields
    url_data = urlparse(request.url)
    return {
        'https': 'on' if request.scheme == 'https' else 'off',
        'http_host': request.host,
        'server_port': url_data.port,
        'script_name': request.path,
        'get_data': request.args.copy(),
        # Uncomment if using ADFS as IdP, https://github.com/onelogin/python-saml/pull/144
        # 'lowercase_urlencoding': True,
        'post_data': request.form.copy()
    }


@app.route('/', methods=['GET', 'POST'])
def index():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    errors = []
    error_reason = None
    not_auth_warn = False
    success_slo = False
    attributes = False
    paint_logout = False

    if 'acs' in request.args:
        request_id = None
        if 'AuthNRequestID' in session:
            request_id = session['AuthNRequestID']

        auth.process_response(request_id=request_id,validate_sign=False)
        errors = auth.get_errors()
        not_auth_warn = not auth.is_authenticated()
        if len(errors) == 0:
            print("Data")
            print(auth.get_attributes())
            print(auth.get_nameid())
            print("---")
            if 'AuthNRequestID' in session:
                del session['AuthNRequestID']
            session['samlUserdata'] = auth.get_attributes()
            session['samlNameId'] = auth.get_nameid()
            session['samlNameIdFormat'] = auth.get_nameid_format()
            session['samlNameIdNameQualifier'] = auth.get_nameid_nq()
            session['samlNameIdSPNameQualifier'] = auth.get_nameid_spnq()
            session['samlSessionIndex'] = auth.get_session_index()
            self_url = OneLogin_Saml2_Utils.get_self_url(req)

            # if 'RelayState' in request.form and self_url != request.form['RelayState']:
            #     return redirect(auth.redirect_to(request.form['RelayState']))
        elif auth.get_settings().is_debug_active():
            error_reason = auth.get_last_error_reason()
            session["samlUserdataError"] = error_reason

    if 'samlUserdata' in session:
        paint_logout = True
        if len(session['samlUserdata']) > 0:
            attributes = session['samlUserdata'].items()
            
    return redirect("/attrs")

@app.route('/attrs/')
def attrs():
    paint_logout = False
    attributes = False
    result = {}
    if 'samlUserdata' in session:
        paint_logout = True
        if len(session['samlUserdata']) > 0:
            attributes = session['samlUserdata']
            result['attributes'] = attributes
            result['nameID'] = session['samlNameId']
    elif 'samlUserdataError' in session:
        result['message'] = session['samlUserdataError']
        return jsonify(result),400

    return jsonify(result)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8000, debug=True)
