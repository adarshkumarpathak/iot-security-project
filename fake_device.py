import requests

# Try to send data WITHOUT authentication
response = requests.post(
    "http://localhost:5000/send-data",
    json={"temperature": 99.9, "humidity": 99.9}
)

print(f"Response: {response.status_code} - {response.json()}")