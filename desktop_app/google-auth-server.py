#!/usr/bin/env python3

"""
Google OAuth Client (No Secret)
This server handles the OAuth flow WITHOUT storing any secrets.
It communicates with the proxy server which adds the client secret.
"""

import http.server
import socketserver
import urllib.parse
import webbrowser
import json
import secrets
import hashlib
import base64
import urllib.request
from urllib.error import HTTPError
import time

# OAuth Configuration (NO SECRET HERE)
CLIENT_ID = '354887056155-otc8l2ocrr0a7qnkbnt8u19bfh0rqudj.apps.googleusercontent.com'
AUTH_URI = 'https://accounts.google.com/o/oauth2/v2/auth'
PROXY_SERVER = 'http://localhost:8888'  # Our proxy server that has the secret
USERINFO_URI = 'https://www.googleapis.com/oauth2/v2/userinfo'
TOKENINFO_URL = 'https://oauth2.googleapis.com/tokeninfo'

# Local server configuration
PORT = 8080
REDIRECT_URI = f'http://localhost:{PORT}/callback'

# Global to store auth results
auth_result = None

def base64_url_encode(data):
    """Base64url encode without padding"""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')

def generate_code_verifier():
    """Generate code verifier for PKCE"""
    return base64_url_encode(secrets.token_bytes(32))

def generate_code_challenge(verifier):
    """Generate code challenge from verifier"""
    digest = hashlib.sha256(verifier.encode('ascii')).digest()
    return base64_url_encode(digest)

class OAuthHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        """Handle OAuth callback"""
        global auth_result
        
        if self.path.startswith('/callback'):
            # Parse query parameters
            query = urllib.parse.urlparse(self.path).query
            params = urllib.parse.parse_qs(query)
            
            if 'code' in params:
                auth_result = {'code': params['code'][0]}
                # Send success page
                self.send_response(200)
                self.send_header('Content-Type', 'text/html')
                self.end_headers()
                html = """
                <html>
                <head><title>Success</title></head>
                <body style="font-family: system-ui; padding: 40px; text-align: center;">
                    <h1 style="color: #22c55e;">Authentication Successful!</h1>
                    <p>You can close this window and return to the terminal.</p>
                </body>
                </html>
                """
                self.wfile.write(html.encode('utf-8'))
            elif 'error' in params:
                auth_result = {'error': params.get('error', ['Unknown'])[0]}
                # Send error page
                self.send_response(200)
                self.send_header('Content-Type', 'text/html')
                self.end_headers()
                error_msg = params.get('error', ['Unknown'])[0]
                html = f"""
                <html>
                <head><title>Error</title></head>
                <body style="font-family: system-ui; padding: 40px; text-align: center;">
                    <h1 style="color: #ef4444;">Authentication Failed</h1>
                    <p>Error: {error_msg}</p>
                </body>
                </html>
                """
                self.wfile.write(html.encode('utf-8'))
        else:
            self.send_error(404)
    
    def log_message(self, format, *args):
        """Suppress default logging"""
        pass

def start_auth_flow():
    """Start OAuth flow with PKCE"""
    # Generate PKCE parameters
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    state = base64_url_encode(secrets.token_bytes(16))
    
    # Build authorization URL
    params = {
        'client_id': CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'response_type': 'code',
        'scope': 'openid email profile',
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256',
        'state': state,
        'access_type': 'offline',
        'prompt': 'consent'
    }
    
    auth_url = f"{AUTH_URI}?{urllib.parse.urlencode(params)}"
    
    print(f"\n📋 Opening browser for authentication...")
    print(f"   If browser doesn't open, visit:\n   {auth_url}\n")
    
    # Open browser
    webbrowser.open(auth_url)
    
    # Start local server to receive callback
    global auth_result
    auth_result = None
    
    with socketserver.TCPServer(("", PORT), OAuthHandler) as httpd:
        print(f"⏳ Waiting for authentication callback on port {PORT}...")
        
        # Wait for one request
        while auth_result is None:
            httpd.handle_request()
    
    if 'error' in auth_result:
        print(f"\n❌ Authentication failed: {auth_result['error']}")
        return None, None
    
    print(f"\n✅ Authorization code received!")
    return auth_result['code'], code_verifier

def exchange_code_for_tokens(auth_code, code_verifier):
    """Exchange authorization code for tokens via proxy server"""
    print("\n🔄 Exchanging code for tokens (via proxy server)...")
    
    # Send request to proxy server (NO CLIENT SECRET HERE)
    params = {
        'grant_type': 'authorization_code',
        'code': auth_code,
        'redirect_uri': REDIRECT_URI,
        'client_id': CLIENT_ID,
        'code_verifier': code_verifier
    }
    
    print(f"→ Sending: grant_type={params['grant_type']}, code={auth_code[:20]}..., verifier={code_verifier[:20]}...")
    
    data = json.dumps(params).encode('utf-8')
    req = urllib.request.Request(
        f'{PROXY_SERVER}/token',
        data=data,
        headers={'Content-Type': 'application/json'}
    )
    
    try:
        with urllib.request.urlopen(req) as response:
            tokens = json.loads(response.read())
            print(f"← Received: access_token={tokens.get('access_token', 'none')[:20]}..., expires_in={tokens.get('expires_in', 'N/A')}s")
            if 'refresh_token' in tokens:
                print(f"← Refresh token: {tokens['refresh_token'][:20]}...")
            return tokens
    except HTTPError as e:
        error_body = e.read().decode('utf-8')
        error_json = json.loads(error_body)
        print(f"← Error: {error_json.get('error', 'unknown')} - {error_json.get('error_description', 'no description')}")
        return None

def refresh_token(refresh_token_value):
    """Refresh access token via proxy server"""
    print("\n🔄 Refreshing access token (via proxy server)...")
    
    # Send request to proxy server (NO CLIENT SECRET HERE)
    params = {
        'grant_type': 'refresh_token',
        'refresh_token': refresh_token_value,
        'client_id': CLIENT_ID
    }
    
    print(f"→ Sending: grant_type={params['grant_type']}, refresh_token={refresh_token_value[:20]}...")
    
    data = json.dumps(params).encode('utf-8')
    req = urllib.request.Request(
        f'{PROXY_SERVER}/token',
        data=data,
        headers={'Content-Type': 'application/json'}
    )
    
    try:
        with urllib.request.urlopen(req) as response:
            tokens = json.loads(response.read())
            print(f"← Received: access_token={tokens.get('access_token', 'none')[:20]}..., expires_in={tokens.get('expires_in', 'N/A')}s")
            return tokens
    except HTTPError as e:
        error_body = e.read().decode('utf-8')
        error_json = json.loads(error_body)
        print(f"← Error: {error_json.get('error', 'unknown')} - {error_json.get('error_description', 'no description')}")
        return None

def get_user_info(access_token):
    """Get user info using access token"""
    print("\n👤 Fetching user information...")
    
    req = urllib.request.Request(
        USERINFO_URI,
        headers={'Authorization': f'Bearer {access_token}'}
    )
    
    try:
        with urllib.request.urlopen(req) as response:
            user_info = json.loads(response.read())
            print("✅ User information received!")
            return user_info
    except HTTPError as e:
        print(f"❌ Failed to get user info: {e}")
        return None

def verify_id_token(id_token_str):
    """Simple ID token verification by decoding JWT"""
    try:
        # Split the JWT token
        parts = id_token_str.split('.')
        if len(parts) != 3:
            return False, "Invalid token format"
        
        # Decode the payload (middle part)
        payload = parts[1]
        # Add padding if needed
        padding = 4 - (len(payload) % 4)
        if padding != 4:
            payload += '=' * padding
        
        decoded = json.loads(base64.urlsafe_b64decode(payload))
        
        # Check expiration
        current_time = time.time()
        exp_time = decoded.get('exp', 0)
        if exp_time < current_time:
            return False, f"Token expired (expired {int(current_time - exp_time)} seconds ago)"
        
        # Check issuer
        if decoded.get('iss') not in ['accounts.google.com', 'https://accounts.google.com']:
            return False, f"Invalid issuer: {decoded.get('iss')}"
        
        # Check audience (should match our client ID)
        if decoded.get('aud') != CLIENT_ID:
            return False, f"Invalid audience: {decoded.get('aud')}"
        
        # Token is valid
        return True, decoded
        
    except Exception as e:
        return False, f"Decode error: {str(e)}"

def verify_access_token(access_token):
    """Verify access token using Google's tokeninfo endpoint"""
    print("   → Calling Google tokeninfo endpoint...")
    try:
        req = urllib.request.Request(
            f"{TOKENINFO_URL}?access_token={access_token}"
        )
        
        with urllib.request.urlopen(req) as response:
            token_info = json.loads(response.read())
            
            # Check if token is valid
            if 'error' in token_info:
                return False, token_info.get('error_description', 'Invalid token')
            
            # Check expiry
            expires_in = token_info.get('expires_in', 0)
            # Convert to int if it's a string
            if isinstance(expires_in, str):
                expires_in = int(expires_in)
            if expires_in <= 0:
                return False, "Token expired"
            
            return True, token_info
            
    except HTTPError as e:
        error_body = e.read().decode('utf-8')
        return False, f"HTTP error: {error_body}"
    except Exception as e:
        return False, f"Request error: {str(e)}"

def display_and_verify_tokens(tokens):
    """Display tokens and verify them"""
    print("\n📦 Tokens Received:")
    print("─" * 50)
    
    # Access Token
    if 'access_token' in tokens:
        print(f"Access Token: {tokens['access_token'][:50]}...")
        print(f"Token Type: {tokens['token_type']}")
        print(f"Expires In: {tokens.get('expires_in', 'N/A')} seconds")
        
        # Verify access token
        print("\n🔍 Verifying Access Token...")
        is_valid, result = verify_access_token(tokens['access_token'])
        if is_valid:
            print(f"   ✅ Access token is valid!")
            print(f"   Scope: {result.get('scope', 'N/A')}")
            print(f"   Email: {result.get('email', 'N/A')}")
            print(f"   Expires in: {result.get('expires_in', 'N/A')} seconds")
        else:
            print(f"   ❌ Access token invalid: {result}")
    
    # Refresh Token
    if 'refresh_token' in tokens:
        print(f"\nRefresh Token: {tokens['refresh_token'][:50]}...")
    
    # ID Token
    if 'id_token' in tokens:
        print(f"\nID Token: {tokens['id_token'][:50]}...")
        
        # Verify ID token
        print("\n🔍 Verifying ID Token...")
        is_valid, claims = verify_id_token(tokens['id_token'])
        if is_valid:
            print(f"   ✅ ID token is valid!")
            print(f"   Email: {claims.get('email', 'N/A')}")
            print(f"   Name: {claims.get('name', 'N/A')}")
            print(f"   Email Verified: {claims.get('email_verified', 'N/A')}")
            exp_time = claims.get('exp', 0)
            remaining = exp_time - time.time()
            print(f"   Expires in: {int(remaining)} seconds")
            print(f"   Issued by: {claims.get('iss', 'N/A')}")
        else:
            print(f"   ❌ ID token invalid: {claims}")

def check_proxy_server():
    """Check if proxy server is running"""
    try:
        req = urllib.request.Request(f'{PROXY_SERVER}/health')
        with urllib.request.urlopen(req, timeout=2) as response:
            return response.status == 200
    except:
        return False

def main():
    """Main flow"""
    print("""
╔════════════════════════════════════════════════════════╗
║     Google OAuth Client (No Secret Stored)             ║
╠════════════════════════════════════════════════════════╣
║  Architecture:                                         ║
║  • This client has NO client secret                    ║
║  • Proxy server handles secret injection               ║
║  • Complete OAuth flow with PKCE                       ║
║                                                        ║
║  Flow: Client → Proxy Server → Google                  ║
╚════════════════════════════════════════════════════════╝
    """)
    
    # Check if proxy server is running
    if not check_proxy_server():
        print(f"""
❌ Proxy server is not running!

Please start the proxy server first:
  python3 google-proxy-server.py

The proxy server handles the client secret securely.
        """)
        return
    
    print("✅ Proxy server is running\n")
    
    # Step 1: Start auth flow
    auth_code, code_verifier = start_auth_flow()
    
    if not auth_code:
        return
    
    # Step 2: Exchange code for tokens (via proxy)
    tokens = exchange_code_for_tokens(auth_code, code_verifier)
    
    if not tokens:
        return
    
    # Display and verify tokens
    display_and_verify_tokens(tokens)
    
    # Step 3: Get user info
    if 'access_token' in tokens:
        user_info = get_user_info(tokens['access_token'])
        
        if user_info:
            print("\n👤 User Information:")
            print("─" * 50)
            print(f"Name: {user_info.get('name', 'N/A')}")
            print(f"Email: {user_info.get('email', 'N/A')}")
            print(f"Picture: {user_info.get('picture', 'N/A')}")
            print(f"ID: {user_info.get('id', 'N/A')}")
            print(f"Verified Email: {user_info.get('verified_email', 'N/A')}")
    
    print("\n✨ OAuth flow complete!")
    
    # Option to test token verification separately
    print("\n" + "─" * 50)
    test_verify = input("\n🔍 Test token verification again? (y/n): ").lower()
    if test_verify == 'y':
        print("\nChoose token to verify:")
        print("1. Access Token")
        print("2. ID Token") 
        print("3. Enter custom token")
        
        choice = input("\nChoice (1-3): ").strip()
        
        if choice == '1' and 'access_token' in tokens:
            print("\n🔍 Re-verifying Access Token...")
            is_valid, result = verify_access_token(tokens['access_token'])
            if is_valid:
                print(f"✅ Still valid! Expires in: {result.get('expires_in')} seconds")
            else:
                print(f"❌ No longer valid: {result}")
        
        elif choice == '2' and 'id_token' in tokens:
            print("\n🔍 Re-verifying ID Token...")
            is_valid, claims = verify_id_token(tokens['id_token'])
            if is_valid:
                remaining = claims.get('exp', 0) - time.time()
                print(f"✅ Still valid! Expires in: {int(remaining)} seconds")
            else:
                print(f"❌ No longer valid: {claims}")
        
        elif choice == '3':
            custom_token = input("Enter token: ").strip()
            # Try as ID token first
            is_valid, result = verify_id_token(custom_token)
            if is_valid:
                print(f"✅ Valid ID token for: {result.get('email')}")
            else:
                # Try as access token
                is_valid, result = verify_access_token(custom_token)
                if is_valid:
                    print(f"✅ Valid access token! Scope: {result.get('scope')}")
                else:
                    print(f"❌ Invalid token: {result}")
    
    # Optionally refresh the access token
    if 'refresh_token' in tokens:
        refresh = input("\n🔄 Test token refresh? (y/n): ").lower()
        if refresh == 'y':
            new_tokens = refresh_token(tokens['refresh_token'])
            
            if new_tokens:
                print("─" * 50)
                print(f"New Access Token: {new_tokens['access_token'][:50]}...")
                print(f"Expires In: {new_tokens.get('expires_in', 'N/A')} seconds")
                
                # Test the new token
                print("\n🧪 Testing new access token...")
                test_req = urllib.request.Request(
                    USERINFO_URI,
                    headers={'Authorization': f'Bearer {new_tokens["access_token"]}'}
                )
                
                try:
                    with urllib.request.urlopen(test_req) as test_response:
                        test_user = json.loads(test_response.read())
                        print(f"✅ New token works! User: {test_user.get('email', 'N/A')}")
                except:
                    print("❌ Failed to verify new token")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Cancelled by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")