import time
import argparse
import dns.message
import dns.rdatatype
import statistics
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  

# Сюда добавить домены/add domains here
domains = [
    'google.com', 'youtube.com', 'facebook.com', 'wikipedia.org', 'instagram.com',
    'bing.com', 'reddit.com', 'x.com', 'chatgpt.com', 'yandex.ru',
    'whatsapp.com', 'amazon.com', 'yahoo.com', 'yahoo.co.jp', 'weather.com',
    'duckduckgo.com', 'tiktok.com', 'temu.com', 'naver.com', 'microsoftonline.com',
    'twitch.tv', 'twitter.com', 'linkedin.com', 'live.com', 'fandom.com',
    'microsoft.com', 'msn.com', 'netflix.com', 'office.com', 'pinterest.com',
    'mail.ru', 'openai.com', 'aliexpress.com', 'paypal.com', 'vk.com',
    'canva.com', 'github.com', 'spotify.com', 'discord.com', 'apple.com', 
    'aistudio.google.com', 'ya.ru'
]

parser = argparse.ArgumentParser(description='DoH test FIXED')
parser.add_argument('--doh-url', default='http://127.0.0.1/dns-query')
parser.add_argument('--insecure', action='store_true', help='SSL ignore (must for IP)')
parser.add_argument('--count', type=int, default=3)
args = parser.parse_args()

session = requests.Session()
session.verify = False if args.insecure else True  

headers = {
    'Content-Type': 'application/dns-message',
    'Accept': 'application/dns-message'
}

print(f'DoH {args.doh_url} insecure={args.insecure}, {args.count}x...\n')

total_success = 0
all_latencies = []

for domain in domains:
    latencies = []
    success = 0
    for _ in range(args.count):
        query_msg = dns.message.make_query(domain, dns.rdatatype.A)
        qdata = query_msg.to_wire()
        start = time.time()
        try:
            r = session.post(args.doh_url, data=qdata, headers=headers, timeout=10)
            r.raise_for_status()
            resp_msg = dns.message.from_wire(r.content)
            end = time.time()
            latency = (end - start) * 1000
            latencies.append(latency)
            ip = str(resp_msg.answer[0][0]) if resp_msg.answer else 'no IP'
            print(f'{domain}: {latency:.2f}мс -> {ip}')
            success += 1
            total_success += 1
        except requests.exceptions.Timeout:
            print(f'{domain}: TIMEOUT')
        except requests.exceptions.HTTPError as e:
            print(f'{domain}: HTTP {e.response.status_code}')
        except requests.exceptions.SSLError as e:
            print(f'{domain}: SSL {e}')
        except requests.exceptions.ConnectionError as e:
            print(f'{domain}: CONNECT {e}')
        except Exception as e:
            print(f'{domain}: {type(e).__name__}: {str(e)[:100]}')
    
    if latencies:
        avg = statistics.mean(latencies)
        all_latencies.append(avg)
        print(f'{domain}: avg {avg:.2f}мс ({success}/{args.count})\n')
    else:
        print(f'{domain}: FAIL\n')

if all_latencies:
    glob_avg = statistics.mean(all_latencies)
    print(f'Всего запросов: {total_success}/{(len(domains)*args.count)}, среднее {glob_avg:.2f}мс')