import fnmatch
from collections import Counter

import jwt

import requests

from urllib.parse import urlencode


def match_path(input_path, pattern):
    input_path = input_path.strip('/')
    pattern = pattern.strip('/')

    return fnmatch.fnmatch(input_path, pattern)


def is_subarray(arr1, arr2):
    counter1 = Counter(arr1)
    counter2 = Counter(arr2)

    for element, count in counter1.items():
        if count > counter2[element]:
            return False

    return True


def convert_string_to_set(str):
    str = str.replace('"', '')
    elements = str[1:-1].split(',')

    # Create a set from the elements
    converted_set = set(element.strip() for element in elements)
    return converted_set


def verify_token_signature(token, public_key_json):
    public_key = public_key_json["publicKey"]
    public_key_pem = (
        f"-----BEGIN PUBLIC KEY-----\n{public_key}\n-----END PUBLIC "
        f"KEY-----")
    algorithm = public_key_json["algorithm"]
    decoded_token = jwt.decode(token, public_key_pem,
                               algorithms=[algorithm],
                               options={"verify_aud": False})
    return decoded_token


def verify_valid_token(token, clientId, clientSecret):
    introspect_token_data = {
        'client_id': clientId,
        'client_secret': clientSecret,
        'token': token
    }
    introspect_token_data = urlencode(introspect_token_data)
    introspect_token_path = ("http://localhost:8080/realms/" +
                             "school_management") + "/protocol/openid" + "-connect/token/introspect"
    response = requests.post(introspect_token_path,
                             data=introspect_token_data, headers={
            'Content-Type': 'application/x-www-form-urlencoded'})
    response = response.json()
    print("okok1234",response)
    if not response['active']:
        return False
    else:
        return True
