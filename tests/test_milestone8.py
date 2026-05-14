from imap_smtp_mcp.config import AppConfig, EndpointConfig, ProtocolMode
from imap_smtp_mcp.capabilities import CapabilityError
from imap_smtp_mcp.errors import InvalidInputError, NotFoundError
from imap_smtp_mcp.read_tools import ReadOnlyMailboxService
from imap_smtp_mcp.capabilities import ensure_action_enabled


def test_error_shape_is_stable() -> None:
    err = InvalidInputError("invalid request")

    assert err.code == "invalid_input"
    assert err.message == "invalid request"
    assert str(err) == "invalid request"


def test_disabled_action_returns_permission_error() -> None:
    config = AppConfig(
        imap=EndpointConfig(host="imap.example.com", port=993, mode=ProtocolMode.SSL),
        smtp=EndpointConfig(host="smtp.example.com", port=465, mode=ProtocolMode.SSL),
        smtp_from_domain=None,
        sent_folder="Sent",
        trash_folder="Trash",
        imap_tls_verify=True,
        imap_tls_ca_bundle_path=None,
        imap_max_retries=2,
        smtp_timeout_seconds=30,
        action_flags={"send_email": False},
        audit_log_dir="/tmp/audit",
    )

    try:
        ensure_action_enabled("send_email", config)
        assert False, "Expected CapabilityError"
    except CapabilityError as exc:
        assert "send_email" in str(exc)


def test_read_email_not_found_shape() -> None:
    class MissingClient:
        def select(self, folder: str):
            return "OK", []

        def uid(self, *args):
            return "NO", []

    class Adapter:
        def connect(self, username: str, password: str):
            return MissingClient()

    service = ReadOnlyMailboxService(Adapter())
    try:
        service.read_email("u", "p", folder="INBOX", uid="99")
        assert False, "Expected NotFoundError"
    except NotFoundError as exc:
        assert exc.code == "not_found"
        assert "99" in exc.message
