from concurrent.futures import ThreadPoolExecutor

import requests
from colorama import Fore, Style
from config import load_config

config = load_config()

_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/124.0 Mobile Safari/537.36",
    "Accept-Language": "en-US,en;q=0.8",
}


def _check(url):
    """True = profil var, False = yok, str = belirsiz (HTTP kodu / hata)."""
    try:
        resp = requests.get(url, headers=_HEADERS, timeout=config.get("timeout", 10),
                            allow_redirects=True)
    except requests.RequestException:
        return "HATA"
    if resp.status_code == 404 or resp.status_code == 410:
        return False
    if resp.status_code == 200:
        return True
    return str(resp.status_code)

def search_username(username):
    """Kullanıcı adını internet genelinde arar."""
    if not username or len(username) < 3:
        print(Fore.RED + "HATA: Kullanıcı adı en az 3 karakter olmalıdır!" + Style.RESET_ALL)
        return

    print(Fore.CYAN + f"\n🔍 '{username}' için arama başlatılıyor...\n" + Style.RESET_ALL)

    # Sosyal medya platformları ve genel siteler
    platforms = {
        "GitHub": f"https://github.com/{username}",
        "Twitter/X": f"https://twitter.com/{username}",
        "Instagram": f"https://www.instagram.com/{username}",
        "Reddit": f"https://www.reddit.com/user/{username}",
        "LinkedIn": f"https://www.linkedin.com/in/{username}",
        "Twitch": f"https://www.twitch.tv/{username}",
        "YouTube": f"https://www.youtube.com/@{username}",
        "Spotify": f"https://open.spotify.com/user/{username}",
        "Pinterest": f"https://www.pinterest.com/{username}",
        "TikTok": f"https://www.tiktok.com/@{username}",
        "Vimeo": f"https://vimeo.com/{username}",
        "DeviantArt": f"https://www.deviantart.com/{username}",
        "Steam": f"https://steamcommunity.com/id/{username}",
        "GitLab": f"https://gitlab.com/{username}",
        "Bitbucket": f"https://bitbucket.org/{username}",
        "HackerRank": f"https://hackerrank.com/{username}",
        "Codeforces": f"https://codeforces.com/profile/{username}",
        "StackOverflow": f"https://stackoverflow.com/users/{username}",
        "Behance": f"https://www.behance.net/{username}",
        "Dribbble": f"https://dribbble.com/{username}",
        "SoundCloud": f"https://soundcloud.com/{username}",
        "Medium": f"https://medium.com/@{username}",
        "Quora": f"https://www.quora.com/profile/{username}",
        "Tumblr": f"https://{username}.tumblr.com",
        "Flickr": f"https://www.flickr.com/people/{username}",
        "About.me": f"https://about.me/{username}",
        "Gravatar": f"https://gravatar.com/{username}",
        "Pastebin": f"https://pastebin.com/u/{username}",
        "Imgur": f"https://imgur.com/user/{username}",
        "ProductHunt": f"https://www.producthunt.com/@{username}",
        "Kaggle": f"https://www.kaggle.com/{username}",
        "Replit": f"https://replit.com/@{username}",
        "CodePen": f"https://codepen.io/{username}",
        "NPM": f"https://www.npmjs.com/~{username}",
        "RubyGems": f"https://rubygems.org/profiles/{username}",
        "PyPI": f"https://pypi.org/user/{username}",
        "DockerHub": f"https://hub.docker.com/u/{username}",
    }

    print(Fore.YELLOW + f"Toplam {len(platforms)} platform taranıyor...\n" + Style.RESET_ALL)

    found = 0
    not_found = 0
    unknown = 0

    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(lambda item: (item[0], item[1], _check(item[1])), platforms.items()))

    for name, url, status in results:
        if status is True:
            print(Fore.GREEN + f"  {'✅ VAR':<10} | {name:<15} | {url}" + Style.RESET_ALL)
            found += 1
        elif status is False:
            print(Fore.RED + f"  {'❌ YOK':<10} | {name:<15} | {url}" + Style.RESET_ALL)
            not_found += 1
        else:
            print(Fore.YELLOW + f"  {'❔ ' + status:<10} | {name:<15} | {url}" + Style.RESET_ALL)
            unknown += 1

    print(Fore.CYAN + Style.BRIGHT + f"\n{'='*60}")
    print(f"Sonuç: {found} platformda VAR, {not_found} platformda YOK, {unknown} belirsiz")
    print("Not: Bazı siteler bot korumasıyla her isteğe aynı yanıtı verir;")
    print("     'VAR' sonuçlarını linke tıklayarak doğrulayın.")
    print(f"{'='*60}" + Style.RESET_ALL)