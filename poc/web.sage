"""
Web interface for an OPAQUE client allowing them to register a username and
password, and login with a username and password in any combination.
It runs a web server for a web browser to connect to for the interface, and
communicates with the OPAQUE server using a socket. Uses the client code in
`client.sage` for the actual registration flow.
"""

from http.server import BaseHTTPRequestHandler, HTTPServer
import logging
import sys

try:
    from sagelib.client import Client
    from sagelib.server import Mode, CONFIG
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

# socket for the web server
# this must be different to the socket for sending data between client and server
WEB_SOCKET = ("localhost", 8080)

# filename to log to that we can read later to display messages sent
LOG_FILE_NAME = "WebClient.log"

# logging format - log everything, to both stderr and the log file with 'client'
# at the start of each message
logging.basicConfig(
    level=logging.INFO,
    format="Client %(levelname)s: %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE_NAME, "w"), # overwrite each time
        logging.StreamHandler() # stderr
    ]
)

def getSkeletonForm(title: str) -> str:
    """
    Return a string of HTML containing a form to enter a username and password.
    This can be inserted between <body></body> tags to form part of an HTML file.
    Title will be the ID of the form, the webpage to POST the form data to, and
    the text on the submit button.
    """

    return f"""
    <p><a href='/'>Home</a></p>
    <form method="post" id={title} action="/{title}">
        <label for="username">Username:</labal>
        <br>
        <input type="text" id="username" name="username">
        <br>
        <label for="password">Password:</label>
        <br>
        <input type="password" id="password" name="password">
        <br>
        <input type="submit" value="{title.title()}">
    </form>
    """

def getSkeletonHTML(title: str, body: str) -> str:
    """
    Return a string containing skeleton code of an HTML file with given title
    and the HTML in 'body' in <body> tags
    """

    return f"""
    <!DOCTYPE html>
    <html>

    <head>
        <title>{title}</title>
    </head>

    <body>
        <h1>{title}</h1>
        {body}
    </body>

    </html>
    """

def formatLog(line: str) -> str:
    """
    Given a 'line' from the log file, format it into a list entry (and
    potentially a sub-list with entries) to go between <li></li> tags to form
    part of an HTML file.
    """

    html = ""
    sub_items = []

    # format 'RegistrationRequest(data={})'
    if line.startswith("RegistrationRequest"):
        data = line.split("=")[1][:-2]
        html += "Registration Request:"
        sub_items.append(f"<b>OPRF Data</b>: {data}")

    # format 'RegistrationResponse(data={}, pkS={})'
    elif line.startswith("RegistrationResponse"):
        spl = line.split("=")
        data = spl[1].split(", ")[0]
        pkS = spl[2][:-2]
        html += "Registration Response:"
        sub_items.extend([f"<b>OPRF Data</b>: {data}",
                          f"<b>Server Public Key</b>: {pkS}"])

    # format 'RegistrationUpload(pkU={}, masking_key={}, envU=Envelope(nonce={}, auth_tag={}))'
    elif line.startswith("RegistrationUpload"):
        spl = line.split("=")
        pkU = spl[1].split(", ")[0]
        masking_key = spl[2].split(", ")[0]
        nonce = spl[4].split(", ")[0]
        auth_tag = spl[5][:-3]
        html += "Registration Upload:"
        sub_items.extend([f"<b>Client Public Key</b>: {pkU}",
                          f"<b>Masking Key</b>: {masking_key}",
                          f"<b>Nonce</b>: {nonce}",
                          f"<b>Auth Tag</b>: {auth_tag}"])

    # format 'CredentialRequest(data={})'
    elif line.startswith("CredentialRequest"):
        data = line.split("=")[1][:-2]
        html += "Credential Request:"
        sub_items.append(f"<b>OPRF Data</b>: {data}")

    # format 'CredentialResponse(data={}, masking_nonce={}, masked_response={})'
    elif line.startswith("CredentialResponse"):
        spl = line.split("=")
        data = spl[1].split(", ")[0]
        masking_nonce = spl[2].split(", ")[0]
        masked_response = spl[3][:-2]
        html += "Credential Response:"
        sub_items.extend([f"<b>OPRF Data</b>: {data}",
                          f"<b>Masking Nonce</b>: {masking_nonce}",
                          f"<b>Masked Response</b>: {masked_response}"])

    # format 'TripleDHMessageInit(nonceU={}, epkU={})'
    elif line.startswith("TripleDHMessageInit"):
        spl = line.split("=")
        nonceU = spl[1].split(", ")[0]
        epkU = spl[2][:-2]
        html += "Triple DH Message Init:"
        sub_items.extend([f"<b>Client Nonce</b>: {nonceU}",
                          f"<b>Ephemeral Client Public Key</b>: {epkU}"])

    # format 'TripleDHMessageRespond(nonceS={}, epkS={}, macS={})
    elif line.startswith("TripleDHMessageRespond"):
        spl = line.split("=")
        nonceS = spl[1].split(", ")[0]
        epkS = spl[2].split(", ")[0]
        mac = spl[3][:-2]
        html += "Triple DH Message Response:"
        sub_items.extend([f"<b>Server Nonce</b>: {nonceS}",
                          f"<b>Ephemeral Server Public Key</b>: {epkS}",
                          f"<b>Server MAC</b>: {mac}"])

    # format 'TripleDHMessageFinish(macU={})
    elif line.startswith("TripleDHMessageFinish"):
        mac = line.split("=")[1][:-2]
        html += "Triple DH Message Finish:"
        sub_items.append(f"<b>Client MAC</b>: {mac}")

    # otherwise just add it verbatim
    else:
        html += line

    # add list tags to the sub list if there is one
    if sub_items:
        html += "<ul>"
        for item in sub_items:
            html += f"<li>{item}</li>"
        html += "</ul>"

    return html

def messages() -> str:
    """
    Return a string of HTML containing a title and an ordered list of the
    messages sent between client and server and keys derived. These are the
    lines in the log file that do not start with 'Client'.
    """

    html = "<h2>Messages Sent/Received and Keys Generated (in hex)</h2><ol>"
    with open(LOG_FILE_NAME) as f:
        for line in f:
            if not line.startswith("Client") and not line.isspace():
                html += f"<li>{formatLog(line)}</li>"
    return html + "</ol>"

# generate static HTML pages
HTML_404      = getSkeletonHTML("404 Not Found"          , "<p>This page does not exist</p>")
HTML_HOME     = getSkeletonHTML("OPAQUE Proof of Concept", "<p><a href=/register>Register</a></p>"
                                                         + "<p><a href=/login>Login</a></p>"
                                                         + "<p><a href=/ake>Login with AKE</a></p>"
                                                         + "<p><a href=/messages>Messages and Keys</a></p>")
HTML_REGISTER = getSkeletonHTML("Register"               , getSkeletonForm("register"))
HTML_LOGIN    = getSkeletonHTML("Login"                  , getSkeletonForm("login"))
HTML_AKE      = getSkeletonHTML("Login with AKE"         , getSkeletonForm("ake"))

def HtmlRegistrationSuccess() -> str:
    """
    Return the HTML for the registration success page seen after submitting a
    username and password for registration and the server succeeding in the
    registration. This needs to be dynamic because the HTML includes the logs
    of all messages sent so far which needs to be updated each time.
    """
    return getSkeletonHTML("Registration Success", f"<p>You have successfully registered.</p><p><a href='/'>Home</a></p>{messages()}")

def HtmlRegistrationFailure() -> str:
    """
    Return the HTML for the registration failure page seen after submitting a
    username and password for registration but the username has already been
    registered. This needs to be dynamic because the HTML includes the logs
    of all messages sent so far which needs to be updated each time.
    """
    return getSkeletonHTML("Registration Failure", f"<p>This username has already been registered, pick a new one.</p><p><a href='/'>Home</a></p>{messages()}")

def HtmlLoginSuccess() -> str:
    """
    Return the HTML for the login success page seen after submitting a username
    and password for login (with or without AKE) and the credentials being
    correct. This needs to be dynamic because the HTML includes the logs of all
    messages sent so far which needs to be updated each time.
    """
    return getSkeletonHTML("Login Success", f"<p>You have successfully logged in.</p><p><a href='/'>Home</a></p>{messages()}")

def HtmlLoginFailure() -> str:
    """
    Return the HTML for the login failure page seen after submitting a username
    and password for login (with or without AKE) and the credentials being
    incorrect. This needs to be dynamic because the HTML includes the logs of all
    messages sent so far which needs to be updated each time.
    """
    return getSkeletonHTML("Login Failure", f"<p>Incorrect username and/or password.</p><p><a href='/'>Home</a></p>{messages()}")

def HtmlMessages() -> str:
    """
    Return the HTML for the messages page that displays all messages sent
    between client and server. This needs to be dynamic because the HTML
    includes the logs of all messages sent so far which needs to be updated
    each time.
    """
    return getSkeletonHTML("Messages and Keys", f"<p><a href=/>Home</a></p>{messages()}")

class MyServer(BaseHTTPRequestHandler):
    """
    Extension of the BaseHTTPRequestHandler class to serve the responses we
    want to valid GET and POST requests
    """

    # instantiate the Client class with the default OPRF configuration
    client = Client(CONFIG)

    def do_GET(self):
        """
        Respond to a GET request.
        If the path is '/' then serve the home page.
        If the path is '/register' then serve the register page.
        If the path is '/login' then serve the login page.
        If the path is '/ake' then serve the login with ake page.
        If the path is '/messages' then serve the messages and keys page.
        Otherwise, serve the 404 Not Found page.
        """

        # if the request was to a valid page then use the relevant HTML
        html = ""
        if self.path == "/":
            html = HTML_HOME
        elif self.path == "/register":
            html = HTML_REGISTER
        elif self.path == "/login":
            html = HTML_LOGIN
        elif self.path == "/ake":
            html = HTML_AKE
        elif self.path == "/messages":
            html = HtmlMessages()

        # if not, send 404 response with the 404 HTML
        if html == "":
            self.send_response(404)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(HTML_404, "utf-8"))

        # if so, send 200 response with the relevant HTML
        else:
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(html, "utf-8"))

    def do_POST(self):
        """
        Respond to a POST request.
        If the path is '/register' then run the registration flow.
        If the path is '/login' then run the login flow without AKE.
        If the path is '/ake' then run the login flow with AKE.
        Otherwise, serve the 404 Not Found page.
        """

        # read the form data into a dictionary
        form_data_str = self.rfile.read(int(self.headers["Content-Length"])).decode().split("&")
        form_data = dict()
        for pair in form_data_str:
            split = pair.split("=")
            form_data[split[0]] = split[1]

        # try retrieving the username and password
        html = ""
        try:
            username = form_data["username"]
            password = form_data["password"]

        # if the form data did not include a username and password then leave
        # html as "" as this is an invalid post request
        except KeyError:
            pass

        # if the username and password were present then proceed
        else:
            logging.info(f"Username: {username}")
            logging.info(f"Password: {password}")

            # if registering, run the client's registration function
            if self.path == "/register":
                success = self.client.do(username, password, Mode.REGISTRATION)

                # if successful, give the registration success HTML
                if success:
                    html = HtmlRegistrationSuccess()

                # otherwise it was unsuccessful so the username has already
                # been registered so give the registration failure HTML
                else:
                    html = HtmlRegistrationFailure()

            # if logging in, run the client's login function
            elif self.path == "/login":
                success = self.client.do(username, password, Mode.LOGIN)

                # if successful, give the login success HTML
                if success:
                    html = HtmlLoginSuccess()

                # otherwise it was unsuccessful so the username and/or
                # password is incorrect so give the login failure HTML
                else:
                    html = HtmlLoginFailure()

            # if logging in with AKE, run the client's login with ake function
            elif self.path == "/ake":
                success = self.client.do(username, password, Mode.LOGIN_AKE)

                # if successful, give the login success HTML
                if success:
                    html = HtmlLoginSuccess()

                # otherwise it was unsuccessful so the username and/or
                # password is incorrect so give the login failure HTML
                else:
                    html = HtmlLoginFailure()

        # if the request was not valid, send 404 response with the 404 HTML
        if html == "":
            self.send_response(404)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(HTML_404, "utf-8"))

        # if it was, send 200 response with the relevant HTML
        else:
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(html, "utf-8"))

# setup the web server
web_server = HTTPServer(WEB_SOCKET, MyServer)

# log that we have started the web interface with the link
logging.info(f"Web interface for client started at http://{WEB_SOCKET[0]}:{WEB_SOCKET[1]}, ctrl+c to exit")

# serve requests forever until ctrl+c
try:
    web_server.serve_forever()
except KeyboardInterrupt:
    web_server.server_close()
    logging.info("Exiting")
