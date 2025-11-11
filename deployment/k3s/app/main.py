from flask import Flask, request

app = Flask(__name__)

@app.route("/")
def home():
    return {"msg": "Hello from App via Envoy!", "client": request.remote_addr}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)

