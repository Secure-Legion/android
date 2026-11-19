"""Check the Android delegated-group migration DDL without opening account data."""
import pathlib
import re
import sqlite3

source = pathlib.Path(__file__).resolve().parent.parent / (
    "app/src/main/java/com/securelegion/database/DelegatedGroupTables.kt"
)
statements = re.findall(r'"(CREATE (?:TABLE|INDEX) [^"\n]+)"', source.read_text())
assert len(statements) >= 20, len(statements)
db = sqlite3.connect(":memory:")
db.execute("PRAGMA foreign_keys=ON")
db.execute("CREATE TABLE groups(groupId TEXT PRIMARY KEY)")
db.execute("CREATE TABLE crdt_op_log(opId TEXT PRIMARY KEY)")
for statement in statements:
    db.execute(statement)
db.execute("INSERT INTO groups(groupId) VALUES ('group')")
db.execute("INSERT INTO crdt_op_log(opId) VALUES ('operation')")
db.execute(
    "INSERT INTO delegated_group_acceptance(op_id,group_id,operation_hash,accepted_at_ms) "
    "VALUES ('operation','group','hash',1)"
)
assert db.execute("PRAGMA foreign_key_check").fetchall() == []
db.execute("DELETE FROM crdt_op_log WHERE opId='operation'")
assert db.execute("SELECT count(*) FROM delegated_group_acceptance").fetchone()[0] == 0
print(f"Verified {len(statements)} migration statements and acceptance cascade")
