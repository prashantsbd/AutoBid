"""
Single-file rough skeleton for:
- Root availability check (same login flow as users)
- Google Sheet credentials
- Robust login + forced password change recovery
- Category-based task execution
- Secure logout (JWT invalidation)
"""

# =========================
# Shared session state
# =========================

class SessionContext:
    def __init__(self):
        self.jwt = None
        self.headers = {}

    def set_jwt(self, jwt: str):
        self.jwt = jwt
        self.headers = {"Authorization": jwt, "Content-Type": "application/json"}

    def clear(self):
        self.jwt = None
        self.headers = {}


# =========================
# Login result types
# =========================

class LoginResult:
    SUCCESS = "success"
    INVALID = "invalid"
    FORCE_PW_CHANGE = "force_pw_change"
    EXPIRED = "expired"


# =========================
# Login service (same for root + users)
# =========================

class LoginService:
    def login(self, creds: dict, session: SessionContext) -> str:
        """
        Performs login call.
        Returns LoginResult.
        """
        response = self._call_login_api(creds)

        if response["status"] == "expired":
            return LoginResult.EXPIRED

        if response["status"] == "invalid":
            return LoginResult.INVALID

        if response["status"] == "force_pw_change":
            return LoginResult.FORCE_PW_CHANGE

        session.set_jwt(response["jwt"])
        return LoginResult.SUCCESS

    def _call_login_api(self, creds):
        # placeholder
        return {"status": "ok", "jwt": "jwt-token"}


# =========================
# Password change recovery
# =========================

class PasswordChangeHandler:
    def recover_login(self, creds: dict, session: SessionContext):
        """
        1. Change to temp password
        2. Login with temp password
        3. Change back to main password
        4. Login again with main password
        """
        temp_pw = "TEMP@123"

        self._change_password(creds["password"], temp_pw)
        creds["password"] = temp_pw

        jwt = self._login_and_get_jwt(creds)
        session.set_jwt(jwt)

        self._change_password(temp_pw, creds["original_password"])
        creds["password"] = creds["original_password"]

        jwt = self._login_and_get_jwt(creds)
        session.set_jwt(jwt)

    def _change_password(self, old, new):
        pass

    def _login_and_get_jwt(self, creds):
        return "jwt-token"


# =========================
# Processing necessity checker (ROOT USER)
# =========================

class ProcessingNecessityChecker:
    def __init__(self, root_creds: dict):
        self.root_creds = root_creds
        self.session = SessionContext()
        self.login_service = LoginService()
        self.pw_handler = PasswordChangeHandler()

    def should_process(self) -> bool:
        result = self.login_service.login(self.root_creds, self.session)

        if result == LoginResult.FORCE_PW_CHANGE:
            self.pw_handler.recover_login(self.root_creds, self.session)

        # even if expired / pw changed → work must proceed
        objects = self._fetch_objects()
        self._logout()

        return bool(objects)

    def _fetch_objects(self):
        # call API using self.session.headers
        return [{"id": 1}]  # empty list means no work

    def _logout(self):
        LogoutService().logout(self.session)


# =========================
# Credential provider
# =========================

class GoogleSheetCredentialProvider:
    def get_users(self):
        return [
            {
                "email": "a@x.com",
                "password": "pw1",
                "original_password": "pw1"
            },
            {
                "email": "b@x.com",
                "password": "pw2",
                "original_password": "pw2"
            }
        ]


# =========================
# Task system
# =========================

class BaseTask:
    def __init__(self, session: SessionContext):
        self.session = session

    def execute(self, obj):
        payload = self.build_payload(obj)
        endpoint = self.endpoint()
        self._send(endpoint, payload)

    def build_payload(self, obj):
        raise NotImplementedError

    def endpoint(self):
        raise NotImplementedError

    def _send(self, endpoint, payload):
        pass


class CategoryATask(BaseTask):
    def build_payload(self, obj):
        return {"id": obj["id"], "type": "A"}

    def endpoint(self):
        return "/task/A"


class CategoryBTask(BaseTask):
    def build_payload(self, obj):
        return {"id": obj["id"], "type": "B"}

    def endpoint(self):
        return "/task/B"


class TaskFactory:
    @staticmethod
    def resolve(obj, session):
        if obj.get("category") == "B":
            return CategoryBTask(session)
        return CategoryATask(session)


class TaskExecutor:
    def __init__(self, session: SessionContext):
        self.session = session

    def execute(self):
        objects = self._fetch_objects()

        for obj in objects:
            if obj.get("action") not in ("inProcess", "edit"):
                task = TaskFactory.resolve(obj, self.session)
                task.execute(obj)

    def _fetch_objects(self):
        return [
            {"id": 1, "category": "A"},
            {"id": 2, "category": "B"}
        ]


# =========================
# Logout (JWT invalidation)
# =========================

class LogoutService:
    def logout(self, session: SessionContext):
        if session.jwt:
            self._invalidate_on_server(session.jwt)
        session.clear()

    def _invalidate_on_server(self, jwt):
        pass


# =========================
# Application runner
# =========================

def run():
    root_creds = {
        "email": "root@sys",
        "password": "rootpw",
        "original_password": "rootpw"
    }

    checker = ProcessingNecessityChecker(root_creds)

    if not checker.should_process():
        print("No objects found. Exiting.")
        return

    users = GoogleSheetCredentialProvider().get_users()
    login_service = LoginService()
    pw_handler = PasswordChangeHandler()

    for user in users:
        session = SessionContext()

        result = login_service.login(user, session)

        if result == LoginResult.FORCE_PW_CHANGE:
            pw_handler.recover_login(user, session)
        elif result != LoginResult.SUCCESS:
            continue

        TaskExecutor(session).execute()
        LogoutService().logout(session)


if __name__ == "__main__":
    run()

