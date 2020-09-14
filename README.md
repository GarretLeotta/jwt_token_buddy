Simple poc of JWT token authorization.

Two docker containers each running a flask server.

Authorization server on port 5050
  GET /get_token
App server on port 5060
  GET /login


Client retrieves a token from the auth server (for now the token contents are hardcoded, but the signing will work for any token)
Client passes that token to the app server via authorization headers

This way, the authorization server holds the password, and the app delegates authorization to that server





~~~~
docker-compose up -d
python test.py
~~~~
