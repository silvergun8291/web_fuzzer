urls = open("./result_urls.txt").read().splitlines()

urls.sort()

for url in urls:
    print(url)
