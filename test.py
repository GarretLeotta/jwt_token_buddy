import requests





class BearerAuth(requests.auth.AuthBase):
    def __init__(self, token):
        self.token = token

    def __call__(self, r):
        r.headers["Authorization"] = "Bearer " + self.token
        return r

#positive test
print("retrieving token from auth server")
url = 'http://localhost:5050/get_token'
res = requests.get(url)
print(res.status_code)
token = res.text

print("passing token to app server")
url = 'http://localhost:5060/login'
res = requests.get(url, auth=BearerAuth(token))
#res = requests.get(url)
print(res.status_code)
print(res.text)



#negative test
print("this test fails")

token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiZ2FycmV0In0.VX3ceH30yyRcGS7gnNHt3IN00VKKr0nG793neiPFMnO5wCyVVADrD472LiJkWLBBK6WkBYC6FbX_dfS3jTwerdeWIiuQxlHNwB0uEK82JBeynKZXoi1Cz3Wpegwh9G6u6Fni82syXPdE5VNx4qXmDgLjYLFpJBG9Haok8DjCUJVuTWheblpU4r73IrmYcl8dl5zeMQqBEq_BQehGAP52INVJ-Z31Nln1_cDoEiFtFhdtsig_gUaw_xLN1EQcf2WSD2Lxgy_zSZIylYS6oS-S436Kb4MRxjwQ_7WaB6K1fEm87fg3zaCW2FvwNQqCfSdXbFGaCAcq8500bME5fB8PEws"

print("2. passing token to app server")
url = 'http://localhost:5060/login'
res = requests.get(url, auth=BearerAuth(token))
#res = requests.get(url)
print(res.status_code)
print(res.text)
