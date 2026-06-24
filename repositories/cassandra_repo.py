# pyrefly: ignore [missing-import]
from cassandra.cluster import Cluster
cluster = Cluster(contact_points=["127.0.0.1"], port=9042)
session = cluster.connect("dev_keyspace")
rows = session.execute("SELECT user_id, first_name, last_name, email FROM users")
for row in rows:
    print(row.first_name, row.last_name, "->", row.email)
cluster.shutdown()