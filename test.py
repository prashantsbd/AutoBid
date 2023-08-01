try:
    import selenium
    from selenium import webdriver
    import chromedriver_autoinstaller
except:
    print("importer has error")

try:
    machine = chromedriver_autoinstaller.install()
except:
    print("driver was now found by this route")

try:
    driver = webdriver.Chrome()
except:
    print("driver pet was not lifted")

try:
    driver.get("https://www.google.com")
    print("omg cloud saw google")
except:
    print("wizard didn't play well")