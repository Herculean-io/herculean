"""Erasure requests: remove the customer's row."""


def erase_customer(cur, customer_id):
    cur.execute("DELETE FROM customers WHERE id = %s", (customer_id,))
