import requests

def check_for_updates(current_version):
    try:
        response = requests.get('https://api.github.com/repos/root0emir/deauthven0m/releases/latest')
        response.raise_for_status() 

        latest_release = response.json()
        latest_version = latest_release['1.1']

        if latest_version != current_version:
            print(f"Update available: {latest_version}. You are currently on {current_version}.")
            print("Visit https://github.com/root0emir/deauthven0m to download the latest version.")
        else:
            print("You are using the latest version.")

    except requests.RequestException as e:
        print(f"Error checking for updates: {e}")

if __name__ == "__main__":
    current_version = '1.0' 
    check_for_updates(current_version)
