try:
    import selenium
    from selenium import webdriver
    from selenium.webdriver.chrome.service import Service
    from webdriver_manager.chrome import ChromeDriverManager
    import chromedriver_autoinstaller
except:
    print("importer has error")

try:
    chromedriver_autoinstaller.install()
except:
    print("driver was now found by this route")