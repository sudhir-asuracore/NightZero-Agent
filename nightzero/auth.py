from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class ReviewerIdentity:
    email: str
    uid: str


class TokenVerifier(Protocol):
    def verify(self, token: str) -> ReviewerIdentity: ...


class FirebaseTokenVerifier:
    def __init__(self) -> None:
        import firebase_admin

        if not firebase_admin._apps:
            firebase_admin.initialize_app()

    def verify(self, token: str) -> ReviewerIdentity:
        from firebase_admin import auth

        decoded = auth.verify_id_token(token)
        email = decoded.get("email")
        uid = decoded.get("uid")
        if not isinstance(email, str) or not isinstance(uid, str):
            raise PermissionError("Firebase token does not contain a reviewer identity")
        return ReviewerIdentity(email=email.lower(), uid=uid)