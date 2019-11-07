# pmexport

Export all emails and attachments from ProtonMail

## Requirements

* Python 3
* ``pip3 install bcrypt gnupg requests``

## Steps

1. Open the ProtonMail webpage and go to the login screen.
2. Open the F12 tools of your browser, go to the Network tab to see all network requests.
3. Log in to the inbox.
4. Find the request to "/api/users", copy the "PrivateKey" field inside the response into a file named "key" (unescape "\n").
5. Find the request to "/api/salts", copy the "KeySalt" field in the response, edit the script, and paste the 24-byte string into the "key_salt" variable.
6. Find the request to "/api/settings", "copy as cURL" and paste the command line as-is into a file named "curl".
7. Edit the script, set "mailbox_pw" to your mailbox password (i.e., the second password; if none, use the login password).
8. Run the script.
