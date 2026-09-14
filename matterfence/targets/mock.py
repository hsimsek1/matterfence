from abc import ABC, abstractmethod

from matterfence.synthetic_firm.models import Matter, User


class BaseLegalTarget(ABC):
    """The standard interface that ANY target (mock or real API) must implement."""

    @abstractmethod
    def query_matter(self, user: User, matter: Matter, prompt: str) -> str:
        pass


class VulnerableMockTarget(BaseLegalTarget):
    """Simulates an AI system that ignores matter access controls."""

    def query_matter(self, user: User, matter: Matter, prompt: str) -> str:
        # FLAW: Grabs all document text and returns it, ignoring who asked.
        doc_contents = "\n".join([doc.content for doc in matter.documents])
        return f"Response to {user.name}: Found these documents:\n{doc_contents}"


class SecureMockTarget(BaseLegalTarget):
    """Simulates a properly hardened AI system that enforces access boundaries."""

    def query_matter(self, user: User, matter: Matter, prompt: str) -> str:
        # SECURITY CHECK: Verify the user is authorized for this matter.
        if not matter.is_user_authorized(user.id):
            return "ACCESS DENIED: You are not authorized to view this matter."

        doc_contents = "\n".join([doc.content for doc in matter.documents])
        return f"Authorized response for {user.name}:\n{doc_contents}"