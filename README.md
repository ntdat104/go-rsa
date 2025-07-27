# RSA Signature Generation and Validation Tool

This web-based tool provides a simple interface for generating RSA key pairs, signing messages with a private key, and verifying those signatures with the corresponding public key. It's a useful utility for understanding the basics of RSA digital signatures and for testing key pairs and signatures.

This tool is built with a frontend using HTML, CSS, and JavaScript, and it relies on a Go-Gin backend for secure and efficient key pair generation. The cryptographic operations (signing and verifying) are performed client-side using the `jsrsasign` library.

---

### Features

-   **RSA Key Pair Generation:** Generates RSA key pairs of different sizes (1024, 2048, 4096 bits) by calling a secure backend API.
-   **Digital Signature Generation:** Signs a plaintext message using the generated private key.
-   **Signature Validation:** Verifies a signature using the public key and the original message, confirming its authenticity and integrity.
-   **Multiple Signature Algorithms:** Supports a variety of RSA signature algorithms, including `RSASSA-PSS` and various `PKCS#1 v1.5` schemes like `SHA256withRSA`.
-   **Base64 Utility:** Includes a built-in tool for encoding and decoding strings to and from Base64 format, which is useful for handling key and signature data.

---

### Prerequisites

To run this tool, you need to have a local web server to serve the `index.html` file and the corresponding Go-Gin backend running.

-   **Go-Gin Backend:** The tool is designed to fetch RSA key pairs from a Go-Gin backend. Ensure your backend is running at `http://localhost:8080` and has an endpoint for key generation. The required endpoint is `GET /generate-rsa-keys?keySize={size}`.
-   **Web Browser:** Any modern web browser that supports JavaScript.
-   **Internet Connection:** The tool uses CDN links for `crypto-js` and `jsrsasign`, so an internet connection is needed on the first load.

---

### How to Use

1.  **Start the Backend:** Ensure your Go-Gin backend is up and running on `http://localhost:8080`.
2.  **Open the Tool:** Open the `index.html` file in your web browser. The tool will automatically attempt to fetch a 2048-bit key pair from the backend on page load.
3.  **Generate a Key Pair:**
    -   Select your desired key size (1024, 2048, or 4096 bits).
    -   Click the **"Generate New Key Pair"** button. The public and private keys will be fetched from the backend and displayed in the text areas.
4.  **Generate a Signature:**
    -   Make sure the **"Generate Signature"** radio button is selected.
    -   Enter your message in the **"ClearText Message"** box.
    -   Choose your desired signature algorithm.
    -   Click the **"Generate Signature"** button. The Base64-encoded signature will appear in the **"Signature Output"** and **"Provide Signature Value"** text areas.
5.  **Verify a Signature:**
    -   Make sure the **"Verify Signature"** radio button is selected.
    -   Ensure the original message is in the **"ClearText Message"** box and the signature is in the **"Provide Signature Value (Base64)"** box.
    -   Choose the same signature algorithm used for generation.
    -   Click the **"Verify Signature"** button. The result will be shown below the button, indicating whether the signature is valid or not.
6.  **Use the Base64 Utility:**
    -   Select either **"Encode to Base64"** or **"Decode from Base64"**.
    -   Enter your text or Base64 string in the input box.
    -   Click the corresponding button to see the result.

---

### Author and Contributors

-   **Author:** [github.com/ntdat104](https://github.com/ntdat104)
-   **Contributor:** [github.com/tuananhlai](https://github.com/tuananhlai)