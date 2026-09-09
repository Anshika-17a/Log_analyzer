import pytest
import datetime
import pandas as pd
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.models.schema import Base, Log, EntityBaseline, Alert
from app.detection.baseline import compute_baselines
from app.detection.ml_anomaly import detect_anomalies

@pytest.fixture
def db_session():
    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()
    yield session
    session.close()

def test_ml_layer_adds_value(db_session):
    logs = []
    now = datetime.datetime.now(datetime.timezone.utc).replace(minute=0, second=0, microsecond=0)
    
    # 1. Normal baseline logs: 50 events over 50 distinct hours
    for i in range(50):
        ts = now - datetime.timedelta(hours=50-i)
        l = Log(id=i+1, ts=ts.isoformat(), user="bob", event="read", resource="/api/normal", ip="10.0.0.1", status="success")
        logs.append(l)
        
    # 2. Anomalous window: touches 10 distinct resources quickly!
    for i in range(10):
        ts = now + datetime.timedelta(minutes=i)
        l = Log(id=60+i, ts=ts.isoformat(), user="bob", event="read", resource=f"/api/secret_{i}", ip="10.0.0.1", status="success")
        logs.append(l)
        
    db_session.bulk_save_objects(logs)
    db_session.commit()
    
    all_logs = db_session.query(Log).all()
    df = pd.DataFrame([l.__dict__ for l in all_logs])
    if '_sa_instance_state' in df.columns:
        df = df.drop(columns=['_sa_instance_state'])
    df['ts'] = pd.to_datetime(df['ts'])
    
    # Compute baseline
    compute_baselines(db_session, df)
    
    # Generate ML alerts (pass empty rule_alerts since no rule would fire for this pure resource spray)
    ml_alerts = detect_anomalies(db_session, df, [])
    
    # Assert
    assert len(ml_alerts) > 0, "ML should have flagged the anomalous window"
    bob_alerts = [a for a in ml_alerts if a['user'] == 'bob']
    assert len(bob_alerts) > 0, "Bob should have an ML alert"
    
    alert = bob_alerts[-1]
    assert alert['rule_id'] == 'ml_anomaly_001'
    assert 'distinct_resources_touched=10' in alert['evidence']
    assert alert['ml_anomaly_score'] >= 0.7
