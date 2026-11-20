"""#104: dump/restore must mirror the application's *explicit* TLS setting.

Legacy CI MariaDB 10.11 has no TLS; MariaDB >=11.4 CLI defaults to TLS.
Never disable TLS for ordinary production database URLs.
"""
from sqlalchemy.engine.url import make_url
from privacyidea.cli.pimanage.backup import _mysql_connection_args


def test_tls_is_not_disabled_by_default():
    url = make_url("mysql+pymysql://u:p@127.0.0.1:3306/database")
    assert _mysql_connection_args(url) == ["-h", "127.0.0.1", "-P", "3306"]


def test_explicit_disabled_tls_matches_pymysql():
    url = make_url("mysql+pymysql://u:p@127.0.0.1:3306/database?ssl_disabled=true")
    assert _mysql_connection_args(url) == ["-h", "127.0.0.1", "-P", "3306", "--skip-ssl"]


def test_explicit_false_preserves_normal_ssl():
    url = make_url("mysql+pymysql://u:p@127.0.0.1:3306/database?ssl_disabled=false")
    assert "--skip-ssl" not in _mysql_connection_args(url)


def test_no_mysql_ssl_exception_for_other_params():
    url = make_url("mysql+pymysql://u:p@db/database?charset=utf8mb4")
    assert _mysql_connection_args(url) == ["-h", "db"]
