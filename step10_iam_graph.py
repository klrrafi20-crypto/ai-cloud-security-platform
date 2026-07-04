"""
STEP 10: Visualize IAM relationships as a graph.

CONCEPT: A graph here means "dots and lines" (nodes and edges), not a
bar chart. Each USER is a dot. Each POLICY they have is another dot.
A line connects a user to each policy they're allowed to use. This
makes it easy to SEE who has broad access, at a glance, instead of
reading a table.
"""

import boto3
from botocore.config import Config
import networkx as nx
import matplotlib.pyplot as plt

my_config = Config(connect_timeout=5, read_timeout=10, retries={"max_attempts": 2})
iam = boto3.client("iam", config=my_config)

HIGH_RISK_POLICIES = ["AdministratorAccess", "IAMFullAccess", "PowerUserAccess"]

# ---- Build the graph ----
G = nx.Graph()

users = iam.list_users()["Users"]

for user in users:
    username = user["UserName"]
    G.add_node(username, node_type="user")

    attached = iam.list_attached_user_policies(UserName=username)
    policy_names = [p["PolicyName"] for p in attached["AttachedPolicies"]]

    for policy in policy_names:
        G.add_node(policy, node_type="policy")
        G.add_edge(username, policy)

# ---- Color nodes: red for risky policies, blue for users, green for safe policies ----
node_colors = []
for node in G.nodes():
    node_type = G.nodes[node].get("node_type")
    if node_type == "user":
        node_colors.append("#4A90D9")  # blue
    elif node in HIGH_RISK_POLICIES:
        node_colors.append("#E74C3C")  # red
    else:
        node_colors.append("#7DCE82")  # green

# ---- Draw and save the graph as an image ----
plt.figure(figsize=(10, 7))
pos = nx.spring_layout(G, seed=42, k=0.8)
nx.draw(
    G, pos, with_labels=True, node_color=node_colors,
    node_size=2000, font_size=8, font_weight="bold",
    edge_color="#999999"
)
plt.title("IAM User -> Policy Relationship Graph")
plt.tight_layout()
plt.savefig("iam_relationship_graph.png", dpi=150)
print("Graph saved as iam_relationship_graph.png")
plt.show()