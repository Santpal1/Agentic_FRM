"""
Velocity metrics from database. Computes transaction frequency per device, email, card, and merchant.
FIX-9: Per-merchant velocity lookup added for bot attack detection.
"""

from datetime import timedelta

def velocity_from_db(row, ts, db_conn):
    """
    Query database for velocity metrics (5min, 1hr, 24hr) on device, email, card.
    Also counts unique cards per device, cards per email in last 24h, and email transaction count.
    """
    cur = db_conn.cursor(dictionary=True)
    dev = row.get('device_id',''); email = row.get('emailId') or row.get('email','')
    card = row.get('card_number',''); ts_s = ts.strftime('%Y-%m-%d %H:%M:%S')
    try:
        for label, delta in [('velocity_5min_count',timedelta(minutes=5)),
                              ('velocity_1hr_count',timedelta(hours=1)),
                              ('velocity_24hr_count',timedelta(hours=24))]:
            cur.execute("SELECT COUNT(*) as cnt FROM transactions WHERE device_id=%s AND purchase_date>=%s AND purchase_date<%s",
                        (dev,(ts-delta).strftime('%Y-%m-%d %H:%M:%S'),ts_s))
            row[label] = cur.fetchone()['cnt']
        cur.execute("SELECT COUNT(DISTINCT card_number) as cnt FROM transactions WHERE device_id=%s AND purchase_date>=%s AND purchase_date<%s",
                    (dev,(ts-timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S'),ts_s))
        row['device_cards_24h'] = cur.fetchone()['cnt']
        cur.execute("SELECT COUNT(DISTINCT card_number) as cnt FROM transactions WHERE email=%s",(email,))
        row['email_cards_total'] = cur.fetchone()['cnt']
        cur.execute("SELECT COUNT(*) as cnt FROM transactions WHERE email=%s",(email,))
        row['email_txn_count'] = cur.fetchone()['cnt']
        cur.execute("SELECT COUNT(*) as cnt FROM transactions WHERE card_number=%s AND purchase_date>=%s AND purchase_date<%s",
                    (card,(ts-timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S'),ts_s))
        row['card_txn_24h'] = cur.fetchone()['cnt']
    finally: cur.close()
    return row

def merchant_velocity_from_db(row, ts, db_conn):
    """
    FIX-9: Per-merchant velocity lookup.
    Counts how many transactions the same card OR device made at this specific merchant
    in the last 5 minutes. Stored as merchant_velocity_5min.
    """
    merchant_id = row.get('merchant_id', '')
    card        = row.get('card_number', '')
    device_id   = row.get('device_id', '')
    ts_s        = ts.strftime('%Y-%m-%d %H:%M:%S')
    since_5m    = (ts - timedelta(minutes=5)).strftime('%Y-%m-%d %H:%M:%S')

    if not merchant_id or not (card or device_id):
        row.setdefault('merchant_velocity_5min', 0)
        return row

    cur = db_conn.cursor(dictionary=True)
    try:
        conds, params = ['merchant_id=%s', 'purchase_date>=%s', 'purchase_date<%s'], [merchant_id, since_5m, ts_s]
        if card and device_id:
            conds.append('(card_number=%s OR device_id=%s)')
            params += [card, device_id]
        elif card:
            conds.append('card_number=%s'); params.append(card)
        else:
            conds.append('device_id=%s'); params.append(device_id)
        cur.execute(f"SELECT COUNT(*) as cnt FROM transactions WHERE {' AND '.join(conds)}", params)
        row['merchant_velocity_5min'] = cur.fetchone()['cnt']
    except:
        row.setdefault('merchant_velocity_5min', 0)
    finally:
        cur.close()
    return row
