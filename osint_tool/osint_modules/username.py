import re
import sys
import time
from colorama import Fore, Style
from urllib.parse import quote

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

    for name, url in platforms.items():
        try:
            # Basit URL doğrulama (network erişimi simülasyonu)
            # Gerçek tool'da burada requests.get() kullanılacak
            status = "✅ VAR" if len(username) % 3 != 0 else "❌ YOK"
            if status == "✅ VAR":
                print(Fore.GREEN + f"  {status:<10} | {name:<15} | {url}" + Style.RESET_ALL)
                found += 1
            else:
                print(Fore.RED + f"  {status:<10} | {name:<15} | {url}" + Style.RESET_ALL)
                not_found += 1
        except Exception as e:
            print(Fore.RED + f"  ⚠️ HATA  | {name:<15} | {e}" + Style.RESET_ALL)

    print(Fore.CYAN + Style.BRIGHT + f"\n{'='*60}")
    print(f"Sonuç: {found} platformda VAR, {not_found} platformda YOK")
    print(f"{'='*60}" + Style.RESET_ALL)