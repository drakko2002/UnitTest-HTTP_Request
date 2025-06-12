import requests
import responses
import unittest

class TestGithubAPI(unittest.TestCase):

    def TestGitAPI(self):
        url = "https://api.github.com"  # Replace with the desired URL
        response = requests.get(url)

        if response.status_code == 200:
            print("Request successful!")
            # Access the content using response.text for text/HTML or response.json() for JSON
            # Example:
            # print(response.text)
            # print(response.json())
        else:
            print(f"Request failed with status code: {response.status_code}")