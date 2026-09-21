class Settings:
    db_password = "Pg7#vQz2Lm9!TrWx"

    def dsn(self):
        return "postgresql://svc:%s@db.internal:5432/app" % self.db_password
