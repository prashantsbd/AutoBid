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
import json
import requests
import gspread
from google.oauth2.service_account import Credentials
from dotenv import load_dotenv
from dataclasses import dataclass, field
from datetime import datetime
import uuid
from typing import Optional
from utils import _int_or_default, _nearest_10_up


load_dotenv()


@dataclass
class UserContext:
    crn: Optional[str] = None
    kitta: Optional[int] = None
    mpin: Optional[str] = None
    price_limit: Optional[float] = None
    email: Optional[str] = None
    boid: Optional[str] = None
    customer_id: Optional[int] = None
    account_number: Optional[str] = None
    account_branch_id: Optional[int] = None
    account_type_id: Optional[int] = None
    bank_id: Optional[int] = None
    demat: Optional[str] = None
    
# @dataclass
# class BatchLog:
#     batch_id: str = field(default_factory=lambda: str(uuid.uuid4()))
#     started_at: datetime = field(default_factory=datetime.utcnow)
#     finished_at: datetime | None = None
#     status: str = "running"   # running | completed | failed
#     total_users: int = 0
#     users_processed: int = 0
#     users_failed: int = 0
#     termination_reason: str | None = None
#
# @dataclass
# class EventLog:
#     timestamp: datetime
#     batch_id: str
#     user_id: str | None
#
#     event_type: str            # LOGIN, TASK_EVALUATION, TASK_SKIPPED
#     entity: str | None         # USER, SHARE
#     entity_id: str | None
#
#     decision: str              # PROCEEDED | SKIPPED | FAILED
#     reason_code: str | None
#     reason_message: str | None
#
#     metadata: dict | None = None
#
#     def to_row(self) -> list[str]:
#         return [
#             self.timestamp.isoformat(),
#             self.batch_id,
#             self.user_id,
#             self.event_type,
#             self.entity,
#             self.entity_id,
#             self.decision,
#             self.reason_code,
#             self.reason_message,
#             json.dumps(self.metadata or {})
#         ]
#
#
# class BufferedEventLogger:
#     def __init__(self, worksheet, flush_threshold: int = 100):
#         self.worksheet = worksheet
#         self.buffer: list[EventLog] = []
#         self.flush_threshold = flush_threshold
#
#     def log(self, event: EventLog):
#         self.buffer.append(event)
#         if len(self.buffer) >= self.flush_threshold:
#             self.flush()
#
#     def flush(self):
#         if not self.buffer:
#             return
#         rows = [event.to_row() for event in self.buffer]
#         self.worksheet.append_rows(rows, value_input_option="USER_ENTERED")
#         self.buffer.clear()


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
        self.user: UserContext | None = None

    def set_jwt(self, jwt: str):
        self.jwt = jwt
        self.headers["Authorization"] = jwt

    def set_user(self, user: UserContext):
        self.user = user

    def clear(self):
        self.jwt = None
        self.user = None
        self.headers.pop("Authorization", None)


# class ExecutionContext:
#     def __init__(self, batch: BatchLog, logger: BufferedEventLogger):
#         self.batch = batch
#         self.logger = logger
#         self.session = SessionContext()
#         self.user_id: str | None = None
#
#     def set_user(self, user_id: str, user_ctx: UserContext):
#         self.user_id = user_id
#         self.session.set_user(user_ctx)



# =========================
# Login result types
# =========================

class LoginResult:
    SUCCESS = "success"
    INVALID = "invalid"
    FORCE_PW_CHANGE = "force_pw_change"
    EXPIRED = "expired"


class BankService:
    def __init__(self, session: SessionContext):
        self.session = session

    def load_bank_details(self):
        user = self.session.user
        # 1. Get bankId
        bank_resp = requests.get(
            os.environ["bank_url"],
            headers=self.session.headers
        )
        bank_resp.raise_for_status()
        bank_id = bank_resp.json()[0]["id"]
        user.bank_id = bank_id

        # 2. Get bank account details
        detail_resp = requests.get(
            f"{os.environ['mybank_url'].rstrip('/')}/{bank_id}",
            headers=self.session.headers
        )
        detail_resp.raise_for_status()
        data = detail_resp.json()[0]

        # 3. Store once in user context
        user.customer_id = data["id"]
        user.account_number = data["accountNumber"]
        user.account_branch_id = data["accountBranchId"]
        user.account_type_id = data["accountTypeId"]

        # 4. Get DEMAT details
        own = requests.get(os.environ["ownDetail_url"], headers=self.session.headers).json()
        user.demat = own["demat"]
        user.boid = own["boid"]


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

        default_kitta = int(os.environ["default_kitta"])
        default_price_limit = int(os.environ["default_price_limit"])
        raw_kitta = _int_or_default(creds.get("Kitta"), default_kitta)

        # ✅ set user context
        user = UserContext(
            crn=creds.get("CRN"),
            kitta=_nearest_10_up(raw_kitta),
            mpin=creds.get("MPin"),
            price_limit=_int_or_default(creds.get("PriceLimit"), default_price_limit),
            email=creds.get("Email")
        )
        self.session.set_user(user)

        # ✅ load bank info ONCE
        BankService(self.session).load_bank_details()

        return LoginResult.SUCCESS

    def logout(self):
        logout_url = os.environ.get("LOGOUT_URL")
        if logout_url and self.session.jwt:
            print(f"Logged out for {self.session.user.boid}")
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
        values = worksheet.get_all_values()
        headers = values[0]
        rows = values[1:]
        return gspread.utils.to_records(headers, rows)
        

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
        elif obj.get("action") == "reapply":
            resp = requests.get(
                f"{os.environ['REAPPLY_DETAILS_URL'].rstrip('/')}/{obj['companyShareId']}",
                headers=self.session.headers
            )
            resp.raise_for_status()

            applicant_form_id = resp.json().get("applicantFormId")

            return f"{os.environ['REAPPLY_TASK_URL'].rstrip('/')}/{applicant_form_id}"
        return os.environ.get("DEFAULT_TASK_URL")


class IPOTask(BaseTask):
    def build_payload(self, obj):
        user = self.session.user
        if not user:
            raise RuntimeError("User not logged in")
        return {
            "demat":user.demat,
            "boid":user.boid,
            "accountNumber":user.account_number,
            "customerId":user.customer_id,
            "accountBranchId":user.account_branch_id,
            "accountTypeId":user.account_type_id,
            "appliedKitta":user.kitta,
            "crnNumber":user.crn,
            "transactionPIN":user.mpin,
            "companyShareId":obj.get("companyShareId"),
            "bankId":user.bank_id
        }


class RightShareTask(BaseTask):
    def build_payload(self, obj):
        user = self.session.user
        if not user:
            raise RuntimeError("User not logged in")
        return {
            "demat":user.demat,
            "boid":user.boid,
            "accountNumber":user.account_number,
            "customerId":user.customer_id,
            "accountBranchId":user.account_branch_id,
            "accountTypeId":user.account_type_id,
            "appliedKitta":user.kitta,
            "crnNumber":user.crn,
            "transactionPIN":user.mpin,
            "companyShareId":obj.get("companyShareId"),
            "bankId":user.bank_id
        }


class TaskFactory:
    @staticmethod
    def resolve(obj, session):
        action = obj.get("action")
        companyShareId = obj["companyShareId"]

        if action in ("edit", "inProcess"):
            # ctx.logger.log(EventLog(
            #     timestamp=datetime.utcnow(),
            #     batch_id=ctx.batch.batch_id,
            #     user_id=ctx.user_id,
            #     event_type="TASK_EVALUATION",
            #     entity="SHARE",
            #     entity_id=companyShareId,
            #     decision="SKIPPED",
            #     reason_code="ALREADY_IN_PROCESS",
            #     reason_message="Share already in process"
            # ))
            return None

        if obj.get("shareGroupName") != "Ordinary Shares":
            return None

        if not TaskFactory._is_account_valid(session, companyShareId):
            return None
        
        if not TaskFactory._is_affordable(session, companyShareId):
            return None

        if obj.get("reservationTypeName") == "RIGHT SHARE":
            return RightShareTask(session)

        elif obj.get("reservationTypeName") == "FOREIGN EMPLOYMENT":
            return None

        elif obj.get("shareTypeName") == "IPO":
            return IPOTask(session)

        return None

    @staticmethod
    def _is_account_valid(session, company_id):
        base_url = os.environ["canApply_url"].rstrip("/")
        demat = session.user.demat

        url = f"{base_url}/{company_id}/{demat}"

        resp = requests.get(url, headers=session.headers)

        return resp.status_code == 202

    @staticmethod
    def _is_affordable(session, company_id):
        company_resp = requests.get(url=f"{os.environ['company_url'].rstrip('/')}/{company_id}", headers=session.headers).json()
        return int(company_resp['sharePerUnit']) <= session.user.price_limit


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
    

# def run():
#     batch = BatchLog()
#     event_ws = gspread_client.open_by_key(...).worksheet("EventLogs")
#     logger = BufferedEventLogger(event_ws)
#
#     ctx = ExecutionContext(batch, logger)
#     login_service = LoginService(ctx.session)
#
#     try:
#         users = GoogleSheetCredentialProvider().get_users()
#         batch.total_users = len(users)
#
#         for user in users:
#             ctx.set_user(user["user_id"], build_user_context(user))
#
#             result = login_service.login(user, ctx)
#             if result != LoginResult.SUCCESS:
#                 batch.users_failed += 1
#                 logger.flush()
#                 continue
#
#             TaskExecutor(ctx).execute()
#             login_service.logout()
#
#             batch.users_processed += 1
#             logger.flush()   # 🔑 flush per user
#
#         batch.status = "completed"
#
#     except Exception as e:
#         batch.status = "failed"
#         batch.termination_reason = str(e)
#         raise
#
#     finally:
#         batch.finished_at = datetime.utcnow()
#         logger.flush()
#         persist_batch_log(batch)
