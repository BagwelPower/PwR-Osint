class OsintError(Exception):
    """Kullanıcıya gösterilecek, beklenen hata (ör. eksik API anahtarı)."""


class MissingApiKey(OsintError):
    def __init__(self, service: str, setting: str):
        super().__init__(f"{service} API anahtarı gerekli. Ayarlardan '{setting}' alanını doldurun.")
        self.service = service
        self.setting = setting


class Cancelled(Exception):
    """Kullanıcı sorguyu iptal etti."""
