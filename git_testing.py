import unittest
import responses
import requests

class TestGitHubOAuth(unittest.TestCase):

    @responses.activate
    def test_get_access_token(self):
        url = "https://github.com/login/oauth/access_token"
        mock_response = {
            "access_token": "mocked_token",
            "token_type": "bearer",
            "scope": "repo"
        }

        responses.add(
            responses.POST,
            url,
            json=mock_response,
            status=200
        )

        # Simulação da requisição de token
        headers = {'Accept': 'application/json'}
        data = {
            'client_id': 'your_client_id',
            'client_secret': 'your_client_secret',
            'code': 'mocked_code'
        }
        response = requests.post(url, headers=headers, data=data)

        # Verificações
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['access_token'], "mocked_token")

if __name__ == '__main__':
    unittest.main()
