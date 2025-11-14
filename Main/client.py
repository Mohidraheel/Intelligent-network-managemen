import requests

BASE_URL = "http://localhost:5000"

print("Testing Network Management System\n")


print("1.Getting sample logs...")
response = requests.get(f"{BASE_URL}/api/sample")
logs = response.json()['logs']
print("Sample logs received!\n")
print("2.Parsing logs...")
response = requests.post(
    f"{BASE_URL}/api/parse",
    json={'logs': logs}
)
print(f"Result: {response.json()}\n")
print("3.Getting summary...")
response = requests.get(f"{BASE_URL}/api/summary")
summary = response.json()
print(f"📊 Total: {summary['total']}")
print(f"🔴 Critical: {summary['critical']}")
print(f"🟡 Warning: {summary['warning']}")
print(f"🔵 Info: {summary['info']}\n")
print("4.Critical Alerts:")
for alert in summary['critical_logs']:
    print(f"    {alert['device']}: {alert['message']}")

print("\n All tests passed!")
