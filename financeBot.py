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
import uuid
import json
import gspread
from datetime import datetime
from google.oauth2.service_account import Credentials
from dotenv import load_dotenv
from dataclasses import dataclass
from typing import Optional
from utils import _int_or_default, _nearest_10_up


load_dotenv()


@dataclass
class UserContext:
    username: Optional[str] = None
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

@dataclass
class BatchLog:
    batch_id: str
    started_at: datetime
    finished_at: datetime | None = None
    status: str = "RUNNING"    # RUNNING | SUCCESS | FAILED
    total_users: int = 0
    users_processed: int = 0
    users_failed: int = 0
    termination_reason: str | None = None
    

@dataclass
class ExecutionLog:
    timestamp: datetime
    batch_id: str
    user_identifier: str | None
    step: str
    action: str
    target: str | None
    outcome: str                 # OK | SKIPPED | FAILED
    reason: str | None
    http: dict | None = None

# =========================
# Shared session context (reused)
# =========================


class SessionContext:
    def __init__(self, batch_id :str):
        self.batch_id = batch_id
        self.jwt = None
        self.headers = {
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json",
        }
        self.user: UserContext | None = None
        self.http = HttpClient(self)
        self.execution_logs: list[ExecutionLog] = []

    def set_jwt(self, jwt: str):
        self.jwt = jwt
        self.headers["Authorization"] = jwt

    def set_user(self, user: UserContext):
        self.user = user

    def clear(self):
        self.jwt = None
        self.user = None
        self.headers.pop("Authorization", None)


class HttpClient:
    def __init__(self, session: SessionContext):
        self.session = session
        self.base_url = os.environ["base_url"].rstrip("/")

    def get(self, path):
        return self._request("GET", path)

    def post(self, path, json):
        return self._request("POST", path, json)

    def _request(self, method, path, json=None):
        path = path.lstrip("/")
        url = f"{self.base_url}/{path}"
        try:
            resp = requests.request(method, url, headers=self.session.headers, json=json) 
            self.session.execution_logs.append(ExecutionLog(
                timestamp=datetime.now(),
                batch_id=self.session.batch_id,
                user_identifier=self.session.user.username if self.session.user else None,
                step="HTTP",
                action=f"{method} {path}",
                target=None,
                outcome="OK" if resp.ok else "FAILED",
                reason=None if resp.ok else resp.text[:120],
                http={
                    "status": resp.status_code
                }
            ))
            return resp
        
        except Exception as e:
            self.session.execution_logs.append(ExecutionLog(
                timestamp=datetime.now(),
                batch_id=self.session.batch_id,
                user_identifier=self.session.user.username if self.session.user else None,
                step="HTTP",
                action=f"{method} {path}",
                target=None,
                outcome="FAILED",
                reason=str(e),
                http=None
            ))
            raise


# =========================
# Login result types
# =========================


class LoginResult:
    SUCCESS = "success"
    INVALID = "invalid"
    FORCE_PW_CHANGE = "force_pw_change"
    EXPIRED = "expired"
    IMMATURE = "immature"


class BankService:
    def __init__(self, session: SessionContext):
        self.session = session

    def load_bank_details(self):
        user = self.session.user
        # 1. Get bankId
        bank_resp = self.session.http.get(
            path=os.environ["bank_path"]
        )
        bank_resp.raise_for_status()
        # TODO: [ ] ensure this layer
        bank_id = bank_resp.json()[0]["id"]
        user.bank_id = bank_id

        # 2. Get bank account details
        detail_resp = self.session.http.get(
            path=f"{os.environ['mybank_path'].rstrip('/')}/{bank_id}" 
        )
        detail_resp.raise_for_status()
        data = detail_resp.json()[0]

        # 3. Store once in user context
        user.customer_id = data["id"]
        user.account_number = data["accountNumber"]
        user.account_branch_id = data["accountBranchId"]
        user.account_type_id = data["accountTypeId"]

        # 4. Get DEMAT details
        own = self.session.http.get(
            path=os.environ["ownDetail_path"]
        ).json()
        user.demat = own["demat"]
        user.boid = own["boid"]


# =========================
# Login service (used everywhere)
# =========================


class LoginService:
    def __init__(self, session: SessionContext):
        self.session = session

    def logout(self):
        logout_path = os.environ.get("LOGOUT_PATH")
        if logout_path and self.session.jwt:
            self.session.http.get(path=logout_path)
        self.session.clear()

    def _call_login_api(self, creds: dict[str, int | str]):
        login_path = os.environ.get("LOGIN_PATH")
        login_payload = {
            "clientId": creds.get("ClientId"),
            "username": creds.get("Username"),
            "password": creds.get("Password"),
        }
        return self.session.http.post(
            path=login_path, json=login_payload
        )

    def login(self, creds: dict[str, int | str]) -> str:
        self.session.clear()
        login = self._call_login_api(creds)

        # invalid password
        if login.status_code == 401:
            self.session.execution_logs.append(ExecutionLog(
                timestamp=datetime.now(),
                batch_id=self.session.batch_id,
                user_identifier=creds.get("Username"),
                step="CREDENTIAL",
                action="CHECK_PASSWORD",
                target=None,
                outcome="SKIPPED",
                reason="UNAUTHORIZED"
            ))
            body = login.json()
            if body.get("errorCode") == 401:
                return LoginResult.INVALID
        body = login.json()

        # priority: expired accounts first
        if body.get("accountExpired") or body.get("dematExpired"):
            self.session.execution_logs.append(ExecutionLog(
                timestamp=datetime.now(),
                batch_id=self.session.batch_id,
                user_identifier=creds.get("Username"),
                step="ACT_HEALTH",
                action="CHECK_VALIDITY",
                target=None,
                outcome="SKIPPED",
                reason="DEMAT/MEROSHARE EXPIRED"
            ))
            return LoginResult.EXPIRED

        if body.get("isTransactionPINReset") or body.get("isTransactionPINNotSetBefore"):
            self.session.execution_logs.append(ExecutionLog(
                timestamp=datetime.now(),
                batch_id=self.session.batch_id,
                user_identifier=creds.get("Username"),
                step="ACT_HEALTH",
                action="CHECK_MATURITY",
                target=None,
                outcome="SKIPPED",
                reason="ACCOUNT_IMMATURE"
            ))
            return LoginResult.IMMATURE

        if body.get("passwordExpired") or body.get("changePassword"):
            self.session.execution_logs.append(ExecutionLog(
                timestamp=datetime.now(),
                batch_id=self.session.batch_id,
                user_identifier=creds.get("Username"),
                step="FORCE",
                action="PW_SCREENING",
                target=None,
                outcome="LOGIN_FREEZE",
                reason="PW_RESET_FORCELY"
            ))
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
            email=creds.get("Email"),
            username=creds.get("Username")
        )
        self.session.set_user(user)

        # ✅ load bank info ONCE
        BankService(self.session).load_bank_details()

        return LoginResult.SUCCESS


# =========================
# Password change handler
# =========================


class PasswordChangeHandler:
    def __init__(self, session: SessionContext, login_service: LoginService):
        # IMPORTANT: session is a shared object reference
        self.session = session
        self.login_service = login_service

    def _change_password(self, old_pw, new_pw):
        pw_change_path = os.environ.get("PW_CHANGE_PATH")
        payload = {
            "oldPassword": old_pw,
            "newPassword": new_pw,
            "confirmPassword": new_pw,
        }
        self.session.http.post(path=pw_change_path, json=payload)

    def recover_login(self, creds: dict[str, int | str]):
        """
        Flow:
        pw-change -> login -> pw-change -> login
        All operations mutate the SAME SessionContext object.
        """
        original_password = creds["Password"]
        temp_pw = "Temp#99"

        # change to temp password (uses current JWT)
        self._change_password(original_password, temp_pw)
        creds["Password"] = temp_pw

        # login with temp password (updates SAME session.jwt)
        self.login_service.login(creds)

        # change back to original password (uses new JWT)
        self._change_password(temp_pw, original_password)
        creds["Password"] = original_password

        # final login (updates SAME session.jwt again)
        return self.login_service.login(creds)


# =========================
# Root processing necessity checker
# =========================


class ProcessingNecessityChecker:
    def __init__(self, creds: dict[str, int | str], login_service: LoginService):
        self.creds = creds
        self.login_service = login_service
        self.pw_handler = PasswordChangeHandler(
            session=login_service.session, login_service=login_service
        )

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
            "filterFieldParams": [
                {"key": "companyIssue.companyISIN.script", "alias": "Scrip"},
                {
                    "key": "companyIssue.companyISIN.company.name",
                    "alias": "Company Name",
                },
                {
                    "key": "companyIssue.assignedToClient.name",
                    "value": "",
                    "alias": "Issue Manager",
                },
            ],
            "page": 1,
            "size": 10,
            "searchRoleViewConstants": "VIEW_OPEN_SHARE",
            "filterDateParams": [
                {"key": "minIssueOpenDate", "condition": "", "alias": "", "value": ""},
                {"key": "maxIssueCloseDate", "condition": "", "alias": "", "value": ""},
            ],
        }
        currentIssue = self.login_service.session.http.post(
            path=os.environ["issues_path"],
            json=issue_payload
        )
        return currentIssue.json()["object"]


# =========================
# Google Sheets credential provider
# =========================


class GoogleSheets:
    def __init__(self):
        scopes = ["https://www.googleapis.com/auth/spreadsheets"]
        creds = Credentials.from_service_account_file("credentials.json", scopes=scopes)
        self.client = gspread.authorize(creds)
        self.sheet = self.client.open_by_key(os.environ["SPREADSHEET_ID"])

    def get_users(self):
        ws = self.sheet.worksheet("Credentials")
        values = ws.get_all_values()
        return gspread.utils.to_records(values[0], values[1:])

    def log_batch(self, batch: BatchLog):
        ws = self.sheet.worksheet("BatchLogs")
        ws.append_row([
            batch.batch_id,
            batch.started_at.isoformat(),
            batch.finished_at.isoformat() if batch.finished_at else "",
            batch.status,
            batch.total_users,
            batch.users_processed,
            batch.users_failed,
            batch.termination_reason or ""
        ])



    def flush_execution_logs(self, logs: list[ExecutionLog]):
        if not logs:
            return

        ws = self.sheet.worksheet("ExecutionLogs")
        rows = [[
            l.timestamp.isoformat(),
            l.batch_id,
            l.user_identifier or "",
            l.step,
            l.action,
            l.target or "",
            l.outcome,
            l.reason or "",
            json.dumps(l.http or {})
        ] for l in logs]
        ws.append_rows(rows)


# =========================
# Task system
# =========================


class BaseTask:
    def __init__(self, session: SessionContext):
        self.session = session

    def execute(self, obj):
        payload = self.build_payload(obj)
        url = self.resolve_endpoint(obj)
        self.session.http.post(path=url, json=payload)

    def build_payload(self, obj):
        raise NotImplementedError

    def resolve_endpoint(self, obj):
        if not obj.get("action"):
            return os.environ.get("DEFAULT_TASK_PATH")
        elif obj.get("action") == "reapply":
            resp = self.session.http.get(
                path=f"{os.environ['reapply_details_path'].rstrip('/')}/{obj['companyShareId']}",
                
            )
            resp.raise_for_status()

            applicant_form_id = resp.json().get("applicantFormId")

            return f"{os.environ['REAPPLY_TASK_PATH'].rstrip('/')}/{applicant_form_id}"
        return os.environ.get("DEFAULT_TASK_PATH")


class IPOTask(BaseTask):
    def build_payload(self, obj):
        user = self.session.user
        if not user:
            raise RuntimeError("User not logged in")
        return {
            "demat": user.demat,
            "boid": user.boid,
            "accountNumber": user.account_number,
            "customerId": user.customer_id,
            "accountBranchId": user.account_branch_id,
            "accountTypeId": user.account_type_id,
            "appliedKitta": user.kitta,
            "crnNumber": user.crn,
            "transactionPIN": user.mpin,
            "companyShareId": obj.get("companyShareId"),
            "bankId": user.bank_id,
        }


class RightShareTask(BaseTask):
    def build_payload(self, obj):
        user = self.session.user
        if not user:
            raise RuntimeError("User not logged in")
        return {
            "demat": user.demat,
            "boid": user.boid,
            "accountNumber": user.account_number,
            "customerId": user.customer_id,
            "accountBranchId": user.account_branch_id,
            "accountTypeId": user.account_type_id,
            "appliedKitta": user.kitta,
            "crnNumber": user.crn,
            "transactionPIN": user.mpin,
            "companyShareId": obj.get("companyShareId"),
            "bankId": user.bank_id,
        }


class TaskFactory:
    @staticmethod
    def resolve(obj, session):
        company_id = obj["companyShareId"]
        user_id = session.user.username if session.user else None

        # already in process
        if obj.get("action") in ("edit", "inProcess"):
            session.execution_logs.append(ExecutionLog(
                timestamp=datetime.now(),
                batch_id=session.batch_id,
                user_identifier=user_id,
                step="ANALYZE",
                action="CHECK_SHARE_STATE",
                target=company_id,
                outcome="SKIPPED",
                reason="ALREADY_IN_PROCESS"
            ))
            return None

        # share group mismatch
        if obj.get("shareGroupName") != "Ordinary Shares":
            session.execution_logs.append(ExecutionLog(
                timestamp=datetime.now(),
                batch_id=session.batch_id,
                user_identifier=user_id,
                step="ANALYZE",
                action="CHECK_SHARE_GROUP",
                target=company_id,
                outcome="SKIPPED",
                reason="NON_ORDINARY_SHARE"
            ))
            return None

        # account validity
        if not TaskFactory._is_account_valid(session, company_id):
            session.execution_logs.append(ExecutionLog(
                timestamp=datetime.now(),
                batch_id=session.batch_id,
                user_identifier=user_id,
                step="ANALYZE",
                action="CHECK_ACCOUNT_VALID",
                target=company_id,
                outcome="SKIPPED",
                reason="ACCOUNT_NOT_ELIGIBLE"
            ))
            return None

        # affordability
        if not TaskFactory._is_affordable(session, company_id):
            session.execution_logs.append(ExecutionLog(
                timestamp=datetime.now(),
                batch_id=session.batch_id,
                user_identifier=user_id,
                step="ANALYZE",
                action="CHECK_AFFORDABILITY",
                target=company_id,
                outcome="SKIPPED",
                reason="UNAFFORDABLE"
            ))
            return None

        # task resolution
        if obj.get("reservationTypeName") == "RIGHT SHARE":
            session.execution_logs.append(ExecutionLog(
                timestamp=datetime.now(),
                batch_id=session.batch_id,
                user_identifier=user_id,
                step="RESOLVE",
                action="RIGHT_SHARE_TASK",
                target=company_id,
                outcome="OK",
                reason=None
            ))
            return RightShareTask(session)

        if obj.get("reservationTypeName") == "FOREIGN EMPLOYMENT":
            session.execution_logs.append(ExecutionLog(
                timestamp=datetime.now(),
                batch_id=session.batch_id,
                user_identifier=user_id,
                step="RESOLVE",
                action="FOREIGN_EMPLOYMENT",
                target=company_id,
                outcome="SKIPPED",
                reason="NOT_SUPPORTED"
            ))
            return None

        if obj.get("shareTypeName") == "IPO":
            session.execution_logs.append(ExecutionLog(
                timestamp=datetime.now(),
                batch_id=session.batch_id,
                user_identifier=user_id,
                step="RESOLVE",
                action="IPO_TASK",
                target=company_id,
                outcome="OK",
                reason=None
            ))
            return IPOTask(session)

        # fallback
        session.execution_logs.append(ExecutionLog(
            timestamp=datetime.now(),
            batch_id=session.batch_id,
            user_identifier=user_id,
            step="RESOLVE",
            action="UNKNOWN_TASK_TYPE",
            target=company_id,
            outcome="SKIPPED",
            reason="NO_MATCHING_TASK"
        ))
        return None

    @staticmethod
    def _is_account_valid(session, company_id):
        base_path = os.environ["canApply_path"].rstrip("/")
        demat = session.user.demat

        url = f"{base_path}/{company_id}/{demat}"

        resp = session.http.get(path=url)

        return resp.status_code == 202

    @staticmethod
    def _is_affordable(session, company_id):
        company_resp = session.http.get(
            path=f"{os.environ['company_path'].rstrip('/')}/{company_id}"
        ).json()
        return int(company_resp["sharePerUnit"]) <= session.user.price_limit


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
            "filterFieldParams": [
                {"key": "companyIssue.companyISIN.script", "alias": "Scrip"},
                {
                    "key": "companyIssue.companyISIN.company.name",
                    "alias": "Company Name",
                },
                {
                    "key": "companyIssue.assignedToClient.name",
                    "value": "",
                    "alias": "Issue Manager",
                },
            ],
            "page": 1,
            "size": 10,
            "searchRoleViewConstants": "VIEW_APPLICABLE_SHARE",
            "filterDateParams": [
                {"key": "minIssueOpenDate", "condition": "", "alias": "", "value": ""},
                {"key": "maxIssueCloseDate", "condition": "", "alias": "", "value": ""},
            ],
        }
        applicableIssue = self.session.http.post(
            path=os.environ["applicable_path"],
            json=applicable_payload
        )
        return applicableIssue.json()["object"]


# =========================
# Application runner
# =========================


def run():
    gsm = GoogleSheets()
    batch = BatchLog(batch_id=str(uuid.uuid4()), started_at=datetime.now())
    session = SessionContext(batch.batch_id)
    login_service = LoginService(session)

    try:
        batch.status = "RUNNING"
        root_creds = {
            "ClientId": int(os.environ["root_clientId"]),
            "Password": os.environ["root_password"],
            "Username": os.environ["root_username"],
        }

        try:
            checker = ProcessingNecessityChecker(root_creds, login_service)
            if not checker.should_process():
                batch.termination_reason = "No objects found."
                batch.status = "SUCCESS"
                return
        finally:
            gsm.flush_execution_logs(session.execution_logs)
            session.execution_logs.clear()

        users = gsm.get_users()
        batch.total_users = len(users)
        pw_handler = PasswordChangeHandler(session=session, login_service=login_service)

        for user in users:
            try:
                result = login_service.login(user)
                if result == LoginResult.FORCE_PW_CHANGE:
                    if pw_handler.recover_login(user) != LoginResult.SUCCESS:
                        print(f"Exception raised for user: {user['User']}")
                        batch.users_failed += 1
                        continue

                elif result != LoginResult.SUCCESS:
                    batch.users_failed += 1
                    continue

                TaskExecutor(session).execute()
                login_service.logout()
                batch.users_processed += 1
            finally:
                gsm.flush_execution_logs(session.execution_logs)
                session.execution_logs.clear()

        batch.status = "SUCCESS"
    except Exception as e:
        batch.status = "FAILED"
        batch.termination_reason = str(e)
        raise

    finally:
        batch.finished_at = datetime.now()
        gsm.log_batch(batch)

if __name__ == "__main__":
    run()
