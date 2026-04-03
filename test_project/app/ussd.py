# Deliberately vulnerable USSD handler
from flask import request

def handle_ussd():
    # Unvalidated USSD inputs
    session_id = request.form["sessionId"]
    phone      = request.form["phoneNumber"]
    service    = request.form["serviceCode"]

    user_input = request.form.get("text", "")
    result = eval(user_input)   # arbitrary code execution
    return result
