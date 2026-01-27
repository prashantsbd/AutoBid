"""
Rough, editable skeleton for:
- Root processing necessity check (same login flow as users)
- Google Sheets credential source
- Robust login + forced password change recovery
- Category-based task execution with dynamic endpoints
- Secure logout with server-side JWT invalidation

Designed for live editing and extension.
"""

import os
import requests
import gspread
from google.oauth2.service_account import Credentials
from dotenv import load_dotenv

load_dotenv()

# =========================
# Shared session context (reused)
# =========================

class SessionContext:
    def __init__(self):
        self.jwt = None
        self.headers = {
            'Accept': 'application/json, text/plain, */*',
            'Content-Type': 'application/json',
        }

    def set_jwt(self, jwt: str):
        self.jwt = jwt
        self.headers["Authorization"] = jwt


    def clear(self):
        self.jwt = None
        self.headers.pop("Authorization", None)


# =========================
# Login result types
# =========================

class LoginResult:
    SUCCESS = "success"
    INVALID = "invalid"
    FORCE_PW_CHANGE = "force_pw_change"
    EXPIRED = "expired"


# =========================
# Login service (used everywhere)
# =========================

class LoginService:
    def __init__(self, session: SessionContext):
        self.session = session

    def _call_login_api(self, creds: dict[str, int | str]):
        login_url = os.environ.get("LOGIN_URL")
        login_payload = {
            "clientId": creds.get("ClientId"),
            "username": creds.get("Username"),
            "password": creds.get("Password"),
        }
        return requests.post(url=login_url, json=login_payload, headers=self.session.headers)

    def login(self, creds: dict[str, int | str]) -> str:
        login = self._call_login_api(creds)

        # invalid password
        if login.status_code == 401:
            body = login.json()
            if body.get("errorCode") == 401:
                return LoginResult.INVALID
        body = login.json()
        # priority: expired accounts first
        if body.get("accountExpired") or body.get("dematExpired"):
            return LoginResult.EXPIRED

        if body.get("passwordExpired") or body.get("changePassword"):
            return LoginResult.FORCE_PW_CHANGE

        jwt_token = login.headers.get("Authorization")
        self.session.set_jwt(jwt_token)
        return LoginResult.SUCCESS

    def logout(self):
        logout_url = os.environ.get("LOGOUT_URL")
        if logout_url and self.session.jwt:
            requests.get(url=logout_url, headers=self.session.headers)
        self.session.clear()


# =========================
# Password change handler
# =========================

class PasswordChangeHandler:
    def __init__(self, session: SessionContext, login_service: LoginService):
        # IMPORTANT: session is a shared object reference
        self.session = session
        self.login_service = login_service

    def recover_login(self, creds: dict[str, int | str]):
        """
        Flow:
        pw-change -> login -> pw-change -> login
        All operations mutate the SAME SessionContext object.
        """
        original_password = creds['password']
        temp_pw = "Temp#99"

        # change to temp password (uses current JWT)
        self._change_password(creds["password"], temp_pw)
        creds["password"] = temp_pw

        # login with temp password (updates SAME session.jwt)
        self.login_service.login(creds)

        # change back to original password (uses new JWT)
        self._change_password(temp_pw, original_password)
        creds["password"] = original_password

        # final login (updates SAME session.jwt again)
        return self.login_service.login(creds)

    def _change_password(self, old_pw, new_pw):
        pw_change_url = os.environ.get("PW_CHANGE_URL")
        payload = {
            "oldPassword": old_pw,
            "newPassword": new_pw
        }
        requests.post(url=pw_change_url, headers=self.session.headers, json=payload)
        pw_change_url = os.environ.get("PW_CHANGE_URL")
        payload = {
            "oldPassword": old_pw,
            "newPassword": new_pw
        }
        # uses shared session.headers
        requests.post(url=pw_change_url, headers=self.session.headers, json=payload)


# =========================
# Root processing necessity checker
# =========================

class ProcessingNecessityChecker:
    def __init__(self, creds: dict[str, int | str], login_service: LoginService):
        self.creds = creds
        self.login_service = login_service
        self.pw_handler = PasswordChangeHandler(session=login_service.session,login_service=login_service)

    def should_process(self) -> bool:
        result = self.login_service.login(self.creds)
        if result == LoginResult.FORCE_PW_CHANGE:
            new_result = self.pw_handler.recover_login(self.creds)
            if new_result != LoginResult.SUCCESS:
                return True
        elif result == LoginResult.EXPIRED or result == LoginResult.INVALID:
            return True
        objects = self._fetch_objects()
        self.login_service.logout()
        return bool(objects)

    def _fetch_objects(self):
        issue_payload = {
            "filterFieldParams":[
                {
                    "key":"companyIssue.companyISIN.script",
                    "alias":"Scrip"
                },
                {
                    "key":"companyIssue.companyISIN.company.name",
                    "alias":"Company Name"
                },
                {
                    "key":"companyIssue.assignedToClient.name",
                    "value":"",
                    "alias":"Issue Manager"
                }
            ],
            "page":1,
            "size":10,
            "searchRoleViewConstants":"VIEW_OPEN_SHARE",
            "filterDateParams":[
                {
                    "key":"minIssueOpenDate",
                    "condition":"",
                    "alias":"",
                    "value":""
                },
                {
                    "key":"maxIssueCloseDate",
                    "condition":"",
                    "alias":"",
                    "value":""
                 }
            ]
        }
        currentIssue = requests.post(url=os.environ['issues_url'], json=issue_payload, headers=self.login_service.session.headers)
        return currentIssue.json()['object']

# =========================
# Google Sheets credential provider
# =========================

class GoogleSheetCredentialProvider:
    def get_users(self):
        sheet_id = os.environ['SPREADSHEET_ID']
        scopes = ["https://www.googleapis.com/auth/spreadsheets"]
        creds = Credentials.from_service_account_file("credentials.json", scopes=scopes)
        client = gspread.authorize(creds)
        workbook = client.open_by_key(sheet_id)
        worksheet = workbook.worksheet('Credentials')
        return worksheet.get_all_records()


# =========================
# Task system
# =========================

class BaseTask:
    def __init__(self, session: SessionContext):
        self.session = session

    def execute(self, obj):
        payload = self.build_payload(obj)
        url = self.resolve_endpoint(obj)
        requests.post(url=url, json=payload, headers=self.session.headers)

    def build_payload(self, obj):
        raise NotImplementedError

    def resolve_endpoint(self, obj):
        if not obj.get('action'):
            return os.environ.get("DEFAULT_TASK_URL")
        elif obj.get('action') == "reapply":
            return os.environ.get("REAPPLY_TASK_URL")
        return os.environ.get("DEFAULT_TASK_URL")


class IPOTask(BaseTask):
    def build_payload(self, obj):
        return {
            "demat":"",
            "boid":"",
            "accountNumber":"",
            "customerId":123,
            "accountBranchId":123,
            "accountTypeId":1,
            "appliedKitta":"",
            "crnNumber":"",
            "transactionPIN":"",
            "companyShareId":"",
            "bankId":""
        }


class RightShareTask(BaseTask):
    def build_payload(self, obj):
        return {"id": obj["id"], "type": "B"}


class TaskFactory:
    @staticmethod
    def resolve(obj, session):
        return None
        if obj.get("category") == "B":  # Update logic
            return RightShareTask(session)
        return IPOTask(session)


class TaskExecutor:
    def __init__(self, session: SessionContext):
        self.session = session

    def execute(self):
        objects = self._fetch_objects()
        for obj in objects:
            task = TaskFactory.resolve(obj, self.session)
            if task:
                task.execute(obj)

    def _fetch_objects(self): 
        applicable_payload = {
            "filterFieldParams":[
                {
                    "key":"companyIssue.companyISIN.script",
                    "alias":"Scrip"
                },
                {
                    "key":"companyIssue.companyISIN.company.name",
                    "alias":"Company Name"
                },
                {
                    "key":"companyIssue.assignedToClient.name",
                    "value":"",
                    "alias":"Issue Manager"
                }
            ],
            "page":1,
            "size":10,
            "searchRoleViewConstants":"VIEW_APPLICABLE_SHARE",
            "filterDateParams":[
                {
                    "key":"minIssueOpenDate",
                    "condition":"",
                    "alias":"",
                    "value":""
                },
                {
                    "key":"maxIssueCloseDate",
                    "condition":"",
                    "alias":"",
                    "value":""
                 }
            ]
        }
        applicableIssue = requests.post(url=os.environ['applicable_url'], json=applicable_payload, headers=self.session.headers)
        return applicableIssue.json()['object']

# =========================
# Application runner
# =========================

def run():
    session = SessionContext()
    login_service = LoginService(session)

    root_creds = {
        "ClientId" : int(os.environ["root_clientId"]),
        "Password" : os.environ["root_password"],
        "Username" : os.environ["root_username"]
    }

    checker = ProcessingNecessityChecker(root_creds, login_service)
    if not checker.should_process():
        print("No objects found. Exiting.")
        return

    users = GoogleSheetCredentialProvider().get_users()
    pw_handler = PasswordChangeHandler(session=session, login_service=login_service)

    for user in users:
        result = login_service.login(user)
        if result == LoginResult.FORCE_PW_CHANGE:
            if pw_handler.recover_login(user) != LoginResult.SUCCESS:
                print(f"Exception raised for user: {user['User']}")
                continue

        elif result != LoginResult.SUCCESS:
            continue

        TaskExecutor(session).execute()
        login_service.logout()


if __name__ == "__main__":
    run()


# for each in response2.json()['object']:
#     if each['shareTypeName'] == "RESERVED":
#         isReserved = True
#         if each['reservationTypeName'] == "FOREIGN EMPLOYMENT":
#             isForeign = True
#         elif each['reservationTypeName'] == "RIGHT SHARE":
#             isRight = True
#     else:
#         isPublic = True
#         break

