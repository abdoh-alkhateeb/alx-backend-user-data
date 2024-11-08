#!/usr/bin/env python3

"""
Defines a bunch of filtering-related logic.
"""


import logging
import os
import re
from typing import List

import mysql.connector

PII_FIELDS = ("name", "email", "phone", "ssn", "password")


def filter_datum(
    fields: List[str], redaction: str, message: str, separator: str
) -> str:
    """
    Returns the log message obfuscated.
    """
    pattern = f"({'|'.join(fields)})=[^{separator}]+"

    return re.sub(
        pattern, lambda match: f"{match.group(1)}={redaction}", message
    )


class RedactingFormatter(logging.Formatter):
    """
    Redacting Formatter class.
    """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields: List[str] = fields

    def format(self, record: logging.LogRecord) -> str:
        """
        Returns a formatted record.
        """
        message = super().format(record)

        return filter_datum(
            self.fields, self.REDACTION, message, self.SEPARATOR
        )


def get_logger() -> logging.Logger:
    """
    Returns a logger object.
    """
    logger = logging.getLogger("user_data")

    logger.setLevel(logging.INFO)
    logger.propagate = False

    handler = logging.StreamHandler()
    formatter = RedactingFormatter(fields=PII_FIELDS)

    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """
    Returns a connector to the database object.
    """
    return mysql.connector.connect(
        user=os.getenv("PERSONAL_DATA_DB_USERNAME", "localhost"),
        password=os.getenv("PERSONAL_DATA_DB_PASSWORD", ""),
        host=os.getenv("PERSONAL_DATA_DB_HOST", "root"),
        database=os.getenv("PERSONAL_DATA_DB_NAME"),
    )


def main():
    """
    Takes no arguments and returns nothing.
    """
    logger = get_logger()
    db = get_db()

    cur = db.cursor()
    cur.execute("SELECT * FROM users")

    fields = [x[0] for x in cur.description]
    rows = cur.fetchall()

    for row in rows:
        msg = "".join(f"{k}={str(v)}; " for k, v in zip(fields, row))
        logger.info(msg)

    db.close()


if __name__ == "__main__":
    main()
