import requests as r

def get_top_n_repos(n):
    url = f'https://api.github.com/search/repositories?q=topic:web&sort=stars&order=desc&per_page={n}&page=1'
    res = r.get(url)
    return res.json()   

print(get_top_n_repos(10)['items'][0])