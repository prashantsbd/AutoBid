try:
    import selenium
    from selenium import webdriver
    from selenium.webdriver.chrome.service import Service
    from webdriver_manager.chrome import ChromeDriverManager

except:
    print("importer has error")

try:
    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()))
except:
    print("driver pet was not lifted")

try:
    driver.get("https://www.google.com")
    print("omg cloud saw google")
except:
    print("wizard didn't play well")