import requests
from bs4 import BeautifulSoup
import re

card_links = []
pdf_pages = []

#Functions
def get_doc_latest_version(link):
    version = re.search(r"\/(\d.\d.\d)\/", link)

    if not version.group(1):
        print("Could not parse version")
        exit()

    version_str = version.group(1)
    last_index = version_str.rfind('.')

    if last_index != -1:
        version = version_str[:last_index] + version_str[last_index+1:]
    else:
        version = version_str
    
    return float(version)

def get_pdf_link(url):
    page = requests.get(link)
    print(page.text)
    soup = BeautifulSoup(page.content, features="lxml")
    element = soup.select('btn-sidebar btn-dark text-center')[0]
    return element.get('onclick')



# MAIN
BASE_URL = "https://docs.fortinet.com"
URL = "https://docs.fortinet.com/product/fortisoar"
page = requests.get(URL)

soup = BeautifulSoup(page.content, "html.parser")
cards = soup.find_all("div", class_="product-card-title")

if len(cards) == 0:
    print("No links found!")
    exit()

for card in cards:
    link = card.find_all("a")[0]
    if link.has_attr('href'):
        card_links.append(link['href'])

#TODO: Store current doc version locally
#print(get_doc_latest_version(card_links[0]))
        


