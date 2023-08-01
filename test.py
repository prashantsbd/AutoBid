try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    import chromedriver_autoinstaller
    from pyvirtualdisplay import Display


except:
    print("importer has error")
try:
    chromedriver_autoinstaller.install()
except:
    print("inst failed")


try:
    display = Display(visible=0, size=(800, 800))
    display.start()

    driver = webdriver.Chrome()
except:
    print("driver pet was not lifted")

try:
    driver.get("https://www.google.com")
    print("omg cloud saw google")
except:
    print("wizard didn't play well")