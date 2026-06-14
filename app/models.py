from datetime import datetime
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
    acl_entries = db.relationship("AclEntry", backref="user", cascade="all, delete-orphan")
    unknown_events = db.relationship("UnknownEvent", backref="user", cascade="all, delete-orphan")
    settings = db.relationship("UserSettings", backref="user", uselist=False, cascade="all, delete-orphan")
    model_versions = db.relationship("ModelVersion", backref="user", cascade="all, delete-orphan")
    
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


class AclEntry(db.Model):
    __tablename__ = "acl_entries"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    ip = db.Column(db.String(45), nullable=False)
    notes = db.Column(db.String(255))
    added_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint("user_id", "ip", name="unique_acl_user_ip"),
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

    training_sample = db.relationship("TrainingSample", backref="event", uselist=False)


class TrainingSample(db.Model):
    __tablename__ = "training_samples"

    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey("unknown_events.id"), unique=True)

    label = db.Column(db.String(20), nullable=False)
    protocol = db.Column(db.Integer)
    flow_iat_mean = db.Column(db.Float)
    tot_fwd_pkts = db.Column(db.Integer)
    pkt_size_avg = db.Column(db.Float)
    flow_duration = db.Column(db.Float)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)


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

    max_log_entries = db.Column(db.Integer, default=200)
    log_system_traffic = db.Column(db.Boolean, default=False)

class ModelVersion(db.Model):
    __tablename__ = "model_versions"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    name = db.Column(db.String(100), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    accuracy = db.Column(db.Float)
    samples = db.Column(db.Integer)
    is_active = db.Column(db.Boolean, default=False)
    deployed_at = db.Column(db.DateTime, default=datetime.utcnow)



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

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=False
    )

    timestamp = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    src_ip = db.Column(db.String(45))
    dst_ip = db.Column(db.String(45))

    src_port = db.Column(db.Integer)
    dst_port = db.Column(db.Integer)

    protocol = db.Column(db.Integer)

    packet_size = db.Column(db.Float, default=0)
    duration = db.Column(db.Float, default=0)

    iat_mean = db.Column(db.Float, default=0)
    iat_std = db.Column(db.Float, default=0)

    fwd_pkts = db.Column(db.Float, default=0)
    bwd_pkts = db.Column(db.Float, default=0)

    fwd_max = db.Column(db.Float, default=0)
    fwd_rate = db.Column(db.Float, default=0)
    fwd_mean = db.Column(db.Float, default=0)
    idle_mean = db.Column(db.Float, default=0)

    pkt_size_avg = db.Column(db.Float, default=0)

    prob_brute = db.Column(db.Float, default=0)
    prob_dos = db.Column(db.Float, default=0)
    prob_adv_dos = db.Column(db.Float, default=0)
    prob_loic = db.Column(db.Float, default=0)
    prob_hoic = db.Column(db.Float, default=0)

    top_threat_type = db.Column(db.String(20))
    max_attack_prob = db.Column(db.Float, default=0)

    action_taken = db.Column(db.String(15), nullable=False)

    all_model_scores = db.Column(db.Text)

    service_name = db.Column(db.String(100))
    app_name = db.Column(db.String(100))
    app_package = db.Column(db.String(200))
    is_system = db.Column(db.Boolean, default=False)