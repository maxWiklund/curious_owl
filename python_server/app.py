# MIT License
#
# Copyright (c) 2024 Max Wiklund
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import binascii

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Flask, jsonify, request

_SUPER_SECRET_KEY = b"anexampleverysecurekey1234567890"
app = Flask(__name__)


@app.route("/endpoint", methods=["POST"])
def process_data():
    data = request.json
    if not "nonce" in data or "message" not in data:
        return (
            jsonify(
                isError=True,
                message="Invalid keys",
                statusCode=400,
            ),
            400,
        )

    ciphertext = binascii.unhexlify(data["message"])
    nonce = binascii.unhexlify(data["nonce"])

    aesgcm = AESGCM(_SUPER_SECRET_KEY)
    decrypted_message = aesgcm.decrypt(nonce, ciphertext, associated_data=None)

    print("Json data: ", request.json)
    print("Decrypted Message:", decrypted_message)

    return (
        jsonify(
            isError=False,
            message="Success",
            statusCode=200,
        ),
        200,
    )


@app.route("/", methods=["GET"])
def home():
    return "Hello"


if __name__ == "__main__":
    app.run(debug=True)
