import requests as r
import os
import subprocess

def get_top_n_repos(n):
    url = f'https://api.github.com/search/repositories?q=web+server+stars:100..2000&sort=stars&order=desc&per_page={n}&page=1'
    res = r.get(url)
    return res.json()

def download_repos(n=20, output_dir="repos"):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    data = get_top_n_repos(n)
    
    if 'items' not in data:
        print(f"Error fetching repositories: {data}")
        return

    for repo in data['items']:
        name = repo['name']
        clone_url = repo['clone_url']
        repo_path = os.path.join(output_dir, name)
        
        if os.path.exists(repo_path):
            print(f"Repository {name} already exists, skipping...")
            continue
            
        print(f"Cloning {name} from {clone_url}...")
        try:
            subprocess.run(['git', 'clone', clone_url, repo_path], check=True)
            print(f"Successfully cloned {name}")
        except subprocess.CalledProcessError as e:
            print(f"Failed to clone {name}: {e}")

if __name__ == "__main__":
    download_repos(20)