import io
import pandas as pd

def export_history_to_csv(rows):
    data = []
    for r in rows:
        data.append({
            "id": r.id,
            "user_id": r.user_id,
            "url": r.url,
            "result": r.result,
            "score": r.score,
            "reasons": r.reasons,
            "created_at": r.created_at
        })
    df = pd.DataFrame(data)
    buf = io.BytesIO()
    df.to_csv(buf, index=False)
    buf.seek(0)
    return buf
