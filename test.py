try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    import chromedriver_autoinstaller



except:
    print("importer has error")
try:
    chromedriver_autoinstaller.install()
except:
    print("inst failed")


try:
    option = webdriver.ChromeOptions()
    option.add_argument("--window-size=1180,650")
    option.add_argument("--headless")
    option.add_argument("--disable-notification")
    option.add_argument("--disable-blink-features=AutomationControlled")
    option.add_argument("--disable-gpu")
    option.add_argument("--disable-webgl")
    driver = webdriver.Chrome(options=option)

except:
    print("driver pet was not lifted")

try:
    driver.get("https://www.google.com")
    print("omg cloud saw google")
except:
    print("wizard didn't play well")