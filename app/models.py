from datetime import datetime
from sqlalchemy.dialects.postgresql import JSONB
from app import db


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    refresh_tokens = db.relationship("RefreshToken", backref="user", cascade="all, delete-orphan")
    blacklist_entries = db.relationship("BlacklistEntry", backref="user", cascade="all, delete-orphan")
    unknown_events = db.relationship("UnknownEvent", backref="user", cascade="all, delete-orphan")
    settings = db.relationship("UserSettings", backref="user", uselist=False, cascade="all, delete-orphan")

    hardware_metrics = db.relationship("HardwareMetric", backref="user", cascade="all, delete-orphan")
    firewall_logs = db.relationship("FirewallLog", backref="user", cascade="all, delete-orphan")

class RefreshToken(db.Model):
    __tablename__ = "refresh_tokens"

    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    revoked = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class BlacklistEntry(db.Model):
    __tablename__ = "blacklist_entries"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    ip = db.Column(db.String(45), nullable=False)
    reason = db.Column(db.String(20), default="manual")
    bf_score = db.Column(db.Float)
    dos_score = db.Column(db.Float)
    notes = db.Column(db.String(255))
    added_at = db.Column(db.DateTime, default=datetime.utcnow)
     #Prevent duplicates.
    __table_args__ = (
        db.UniqueConstraint("user_id", "ip", name="unique_blacklist_user_ip"),
    )


class UnknownEvent(db.Model):
    __tablename__ = "unknown_events"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    src_ip = db.Column(db.String(45))
    src_port = db.Column(db.Integer)
    dst_port = db.Column(db.Integer)
    protocol = db.Column(db.Integer)
    size_bytes = db.Column(db.Integer)

    flow_iat_mean = db.Column(db.Float)
    tot_fwd_pkts = db.Column(db.Integer)
    pkt_size_avg = db.Column(db.Float)
    flow_duration = db.Column(db.Float)

    bf_score = db.Column(db.Float)
    dos_score = db.Column(db.Float)

    status = db.Column(db.String(20), default="pending")
    label = db.Column(db.String(20))

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    reviewed_at = db.Column(db.DateTime)


class UserSettings(db.Model):
    __tablename__ = "user_settings"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), unique=True, nullable=False)

    block_threshold = db.Column(db.Float, default=0.20)
    warn_threshold = db.Column(db.Float, default=0.10)

    flood_detection = db.Column(db.Boolean, default=True)
    syn_flood_detection = db.Column(db.Boolean, default=True)

    flood_pkt_per_sec = db.Column(db.Integer, default=1000)
    syn_flood_per_sec = db.Column(db.Integer, default=100)

    bf_model_enabled = db.Column(db.Boolean, default=True)
    dos_model_enabled = db.Column(db.Boolean, default=True)
    hulk_model_enabled = db.Column(db.Boolean, default=True)
    loic_model_enabled = db.Column(db.Boolean, default=True)
    hoic_model_enabled = db.Column(db.Boolean, default=True)

    max_log_entries = db.Column(db.Integer, default=200)
    log_system_traffic = db.Column(db.Boolean, default=False)


class HardwareMetric(db.Model):
    __tablename__ = "hardware_metrics"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=False
    )

    cpu_usage = db.Column(db.Float, nullable=False)

    ram_used_mb = db.Column(db.Integer, nullable=False)

    ram_total_mb = db.Column(db.Integer, nullable=False)

    battery_level = db.Column(db.Float)

    recorded_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )




class FirewallLog(db.Model):
    __tablename__ = "firewall_logs"

    # Columns map 1:1 to the firewall-log WebSocket wire contract (see
    # docs/DATABASE_SCHEMA.md and the Flutter client's TrafficBloc._toLogJson),
    # plus the server-owned id / user_id / received_at fields.
    id = db.Column(db.BigInteger, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=False
    )

    src_ip = db.Column(db.String(45))
    dst_ip = db.Column(db.String(45))              # destination IP of the connection
    src_port = db.Column(db.Integer)
    dst_port = db.Column(db.Integer)

    protocol = db.Column(db.SmallInteger)          # 0/1/6/17
    size_bytes = db.Column(db.Integer)

    # Network-flow features.
    duration = db.Column(db.Float)                 # flow duration in seconds
    fwd_pkts = db.Column(db.Integer)               # forward-direction packet count
    bwd_pkts = db.Column(db.Integer)               # backward-direction packet count
    fwd_rate = db.Column(db.Float)                 # forward packet rate (packets/sec)

    selected_model = db.Column(db.String(100))
    selected_score = db.Column(db.Float)           # [0, 1]
    all_model_scores = db.Column(JSONB)            # {"BF_v1": 0.92, ...}

    action = db.Column(db.String(10), nullable=False)   # blocked|warned|allowed
    threat_type = db.Column(db.String(50))

    service_name = db.Column(db.String(100))
    app_name = db.Column(db.String(100))
    app_package = db.Column(db.String(200))
    is_system = db.Column(db.Boolean, nullable=False, default=False)

    # Device clock (taken from the payload) vs. server-side receipt time.
    created_at = db.Column(db.DateTime(timezone=True), nullable=False)
    received_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=datetime.utcnow
    )

    __table_args__ = (
        db.Index("ix_fwlogs_user_created", "user_id", created_at.desc()),
        db.Index("ix_fwlogs_user_action", "user_id", "action"),
    )