from paramminer import *

print(url_exists('http://www.example.com'))
print(url_exists('http://www.notvalidcuzitsnotvalid.com/'))

url = "https://ac271fc61fcbe8a4c03449c4000f008c.web-security-academy.net/"
regex = re.compile("(?<=://)[^/\n]*")
print(regex.search(url).group())