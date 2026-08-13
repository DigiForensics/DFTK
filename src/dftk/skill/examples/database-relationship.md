# Example — database relationship

Question: “Which customer-service account belongs to the conversation?”

Inventory the relevant tables and keys. Identify the conversation's stable account/customer-service ID, then join to the identity table. A display name search is a discovery step, not a reliable join when names can collide.
