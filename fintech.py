import os
import time
import requests
from tabulate import tabulate
from dotenv import load_dotenv
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.keys import Keys
from selenium.common.exceptions import TimeoutException


def envcall(array):
    load_dotenv()
    return os.environ[array].split(", ")


def xpath_donot_need(driver, path, value):
    return driver.find_element(By.XPATH, path).text != value


def login(company, clientid, pw):
    try:
        time.sleep(5)
        WebDriverWait(driver, 10).until(EC.visibility_of_element_located((By.XPATH, "//select2")))
    except:
        print("Page title is: ", driver.title)
        print("Current URL: ", driver.current_url)
        driver.refresh()
    driver.find_element(By.XPATH, "//select2").click()
    WebDriverWait(driver, 10).until(EC.visibility_of_element_located((By.XPATH, "//input[@class='select2-search__field']")))
    capital = driver.find_element(By.XPATH, "//input[@class='select2-search__field']")
    capital.send_keys(company)
    capital.send_keys(Keys.ENTER)
    driver.find_element(By.ID, "username").send_keys(clientid)
    driver.find_element(By.ID, "password").send_keys(pw)
    driver.find_element(By.XPATH, "//button[@class='btn sign-in']").click()


def user_changed_pw():
    try:
        WebDriverWait(driver, 5).until(url_changed)
    except:
        try:
            msg = driver.find_element(By.XPATH, "//div[@class='toast-message']").text
            if msg == 'Something went wrong':
                return 'retry'
            else:
                clear_toast()
                print(f"User: {User[w]} changed pw. {msg}")
                driver.find_element(By.ID, "username").clear()
                driver.find_element(By.ID, "password").clear()
                return 'continue'
        except:
            print("retrial for login case triggered")
            driver.refresh()
            return 'retry'


def url_changed(driver):
    return driver.current_url != initial_url


def change_password(old_pw, new_pw):
    driver.implicitly_wait(10)
    driver.find_element(By.ID, "oldPassword").send_keys(old_pw)
    driver.find_element(By.ID, "newPassword").send_keys(new_pw)
    driver.find_element(By.ID, "confirmPassword").send_keys(new_pw)
    WebDriverWait(driver, 10).until(EC.element_to_be_clickable((By.XPATH, "//div[@class='form-group form-actions']/button")))
    driver.find_element(By.XPATH, "//div[@class='form-group form-actions']/button").click()
    clear_toast()


def dynamic_pw_change(company, clientid, pw, user):
    new_pw = pw+'a'
    change_password(pw, new_pw)
    login(company, clientid, new_pw)
    driver.find_element(By.ID, 'dropdownMenuButton').click()
    driver.implicitly_wait(3)
    driver.find_element(By.ID, 'tab2-link').click()
    change_password(new_pw, pw)
    login(company, clientid, pw)
    print(f"dynamic case hit: {user}")
    WebDriverWait(driver, 5).until(url_changed)


def apply_ipo(crn, mpin):
    WebDriverWait(driver, 10).until(EC.visibility_of_element_located((By.ID, "selectBank")))
    driver.find_element(By.ID, "selectBank").click()
    driver.find_element(By.XPATH, "//select[@id='selectBank']/option[2]").click()
    WebDriverWait(driver, 10).until(
        EC.visibility_of_element_located((By.CSS_SELECTOR, "#accountNumber"))
    )
    driver.find_element(By.ID, "accountNumber").click()
    driver.find_element(By.XPATH, "//select[@id='accountNumber']/option[2]").click()
    driver.find_element(By.ID, "appliedKitta").send_keys(10)
    driver.find_element(By.ID, "crnNumber").send_keys(crn)
    driver.find_element(By.ID, "disclaimer").click()
    WebDriverWait(driver, 10).until(
        EC.element_to_be_clickable((By.XPATH, "//div[@class='card-footer']/button[1]"))
    )
    driver.find_element(By.XPATH, "//div[@class='card-footer']/button[1]").click()
    WebDriverWait(driver, 10).until(
        EC.visibility_of_element_located((By.ID, 'transactionPIN'))
    )
    driver.find_element(By.ID, 'transactionPIN').send_keys(mpin)
    WebDriverWait(driver, 10).until(
        EC.element_to_be_clickable((By.XPATH,
                                    "/html/body/app-dashboard/div/main/div/app-issue/div/wizard/div/wizard-step[2]/div[2]/div/form/div[2]/div/div/div/button[1]"))
    )
    driver.find_element(By.XPATH,
                        "/html/body/app-dashboard/div/main/div/app-issue/div/wizard/div/wizard-step[2]/div[2]/div/form/div[2]/div/div/div/button[1]").click()


def clear_toast():
    num_toast = len(driver.find_elements(By.XPATH, "//div[@class='toast-bottom-right']//button"))
    try:
        for a in range(num_toast):
            driver.find_element(By.XPATH, "//div[@class='toast-bottom-right']//button").click()
    except:
        pass


def DB_call():
    data = list(zip(User, Status))
    headers = ['USER', 'STATUS']
    table = tabulate(data, headers=headers, tablefmt='rst', colalign=("left", "center"))
    return table
    # data = list(zip(User, ClientID, Password, CRN, MPin, Status))
    # headers = ['USER', 'ID', 'PASSWORD', 'CRN', 'MPIN', 'STATUS']


def chrome_setup():
    option = webdriver.ChromeOptions()
    # headless = input("Want Head? y/n\n Ans: ")
    # if headless == "n":
    option.add_argument("--headless")
    option.add_argument("--window-size=1180,650")
    option.add_argument("--disable-notification")
    option.add_argument("--disable-blink-features=AutomationControlled")
    option.add_argument("--disable-gpu")
    option.add_argument("--disable-webgl")
    option.add_argument("--disable-cache")
    driver = webdriver.Chrome(options=option)
    return driver


def add_to_report():
    if j == i:
        Status.insert(w, each_status)


def terminator(admin_msg):
    dashboard = DB_call()
    admin_msg += msg_formatter(dashboard)
    admin_msg += msg_formatter(time.time() - start_time)
    bot_send_msg(admin_msg)
    quit()


def msg_formatter(message):
    tmp_msg = f"{message}\n"
    return tmp_msg


def bot_send_msg(admin_msg):
    message = {
        'content': admin_msg
    }
    # bot_url = 'https://discord.com/api/webhooks/' + os.getenv("WEBHOOK_TOKEN")
    bot_url = os.getenv("WEBHOOK_TOKEN")
    headers = {
        'Content-Type': 'application/json',
    }
    requests.post(url=bot_url, json=message, headers=headers)
    return 1


driver = chrome_setup()

start_time = time.time()
User = envcall("User")
cptl = envcall("cptl")
ClientID = envcall("ClientID")
Password = envcall("Password")
MPin = envcall("MPin")
CRN = envcall("CRN")
url = envcall("URL")
Status = []
admin_msg = ""
dashboard_url = url[0]
renew_url = [url[1], url[4]]
# demat/demat and meroshare
password_forced_url = url[2]
initial_url = url[3]
patience = 50

driver.set_page_load_timeout(patience)

# Ordinary Shares / Debentures / Close Ended Mutual Fund
max_attempts = 3
for attempt in range(1, max_attempts + 1):
    try:
        driver.get(initial_url)
        break  # Exit loop if successful
    except TimeoutException as e:
        admin_msg += msg_formatter(f"Attempt {attempt} failed due to timeout: {e}")
        print(f"Attempt {attempt} failed due to timeout: {e}")
        if attempt == max_attempts:
            print("All retry attempts failed.")
            raise  # Re-raise the exception if it's the last attempt

# TASK: jaba apply hunxa teti bela sabai vanda tallo ko toast msg match garna parxa
# TASK: server call self defined function rakhnay ani make sure that int(.text) >= 0
# TASK: Right share
# TASK: tyo something went wrong wala portion lai thap optimize garnu parxa
# TASK: data lai multi dimension array 2D
'''Context:
1. applied kitta afai aauxa auto
2. minimum quantity wala get lai adjust garna parxa->jugad wala tyo server ko
3. 6th account lai right aairaxa ma first act ma matra gaye vane how can I see the rights ???
4. 20 days gap dera aauni raixa right'''

w = -1
minimum = 99
maximum = 220
for element in ClientID:
    w += 1
    each_status = []
    apply_count = 0
    try:
        # TASK: login anyhow garaunu login function ko kam ho don't make code dirty at this place
        login(cptl[w], ClientID[w], Password[w])

        if user_changed_pw() == 'continue':
            Status.append("PW Changed")
            continue
        elif user_changed_pw() == 'retry':
            driver.get(initial_url)
            login(cptl[w], ClientID[w], Password[w])
            user_changed_pw()

        if driver.current_url == dashboard_url:
            pass
        elif driver.current_url == renew_url[0] or renew_url[1]:
            if driver.current_url == renew_url[0]:
                Status.append("Demat Renew")
                admin_msg += msg_formatter(f"{w + 1}: Renew Demat: {ClientID[w]}, User:{User[w]}\nPrice: 100")
            else:
                Status.append("Renew all")
                admin_msg += msg_formatter(f"{w + 1}: Renew Demat and Meroshare: {ClientID[w]}, User:{User[w]}\nPrice: 150")
            # CASE: mail garna paryo
            driver.get(initial_url)
            continue
        elif driver.current_url == password_forced_url:
            admin_msg += msg_formatter(f"{User[w]} ko password ko lagi kam garna paryo")
            dynamic_pw_change(cptl[w], ClientID[w], Password[w], User[w])
        else:
            admin_msg += msg_formatter({driver.current_url})
            driver.get(initial_url)
            continue
        driver.implicitly_wait(2)
        try:
            driver.find_element(By.LINK_TEXT, "My ASBA").is_displayed()
        except:
            driver.refresh()
            admin_msg += msg_formatter("Dashboard was only visible master")
            driver.implicitly_wait(3)

        # clear_toast()
        driver.find_element(By.LINK_TEXT, "My ASBA").click()
        driver.implicitly_wait(5)
        companies = driver.find_elements(By.XPATH, "//div[@class='company-list']")
        i = len(companies)
        j = 0
        for j in range(1, i + 1):
            mainblock = f"//div[@class='company-list'][{j}]"
            driver.implicitly_wait(3)
            # HAZARD: useless function xpath_donot_need
            xpath_donot_need(driver, f"{mainblock}/div[1]/div[1]/div/span[5]", "")
            sharegroup = driver.find_element(By.XPATH, f"{mainblock}/div[1]/div[1]/div/span[5]").text
            sharetype = driver.find_element(By.XPATH, f"{mainblock}//span[4]").text
            share = driver.find_element(By.XPATH, f"{mainblock}//span[1]").text
            try:
                button = driver.find_element(By.XPATH, f"{mainblock}//button")
            except:
                each_status.append("2nd_Time")
                add_to_report()
                continue
            if (sharegroup == "Ordinary Shares") and (sharetype == "IPO" or "FPO"):
                if button.text == "Apply":
                    pass
                elif button.text == "Edit":
                    each_status.append("Self")
                    add_to_report()
                    admin_msg += msg_formatter(f"already applied of {User[w]}")
                    apply_count += 1
                    continue
                else:
                    admin_msg += msg_formatter("Warning")
            else:
                each_status.append("NULL")
                add_to_report()
                continue
            button.click()
            WebDriverWait(driver, 10).until(
                EC.visibility_of_element_located((By.CLASS_NAME, "section-block"))
            )
            WebDriverWait(driver, 3).until(
                EC.text_to_be_present_in_element((By.XPATH, "//div[@class='col-md-4'][8]//span"), "10"))
            PPS = driver.find_element(By.XPATH, "//div[@class='col-md-4'][5]//span").text
            if minimum > float(PPS) or float(PPS) > maximum:
                driver.back()
                admin_msg += msg_formatter(f"Unaffordable->{float(PPS)}")
                each_status.append(f"Unaffordable->{float(PPS)}")
                add_to_report()
                clear_toast()
                continue
            elif float(PPS) in range(minimum, maximum):
                pass
            else:
                admin_msg += msg_formatter("unknown error occured")
                quit()
            apply_ipo(CRN[w], MPin[w])
            apply_count += 1
            # TASK: see the toast msg and optimize
            admin_msg += msg_formatter(f"{w+1}: applied: {share}, user: {User[w]}")
            # CASE: paisa xa ke nai herna paryo
            clear_toast()
            each_status.append("Success")
            add_to_report()
        if i == 0 or apply_count == 0:
            admin_msg += msg_formatter("NO OFFERING")
            if w >= len(Status):
                each_status.append("NO OFFERING")
                add_to_report()
            else:
                Status[w] = "NO OFFERING"
            terminator(admin_msg)
        driver.find_element(By.XPATH, "//ul[@class='header-menu__list']/li[1]/a").click()
    except Exception as e:
        admin_msg += msg_formatter(f"WARNING: exception occured for {ClientID[w]}, {User[w]}")
        if Status[w] is None:
            User.append(User[w])
            cptl.append(cptl[w])
            ClientID.append(ClientID[w])
            Password.append(Password[w])
            MPin.append(MPin[w])
            CRN.append(CRN[w])
            Status.append("exception")
        driver.get(initial_url)
terminator(admin_msg)