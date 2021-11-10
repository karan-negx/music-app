from enum import unique
from app import db
from app import db
from flask_sqlalchemy import sqlalchemy

class LikedVideos(db.Model):

    id = db.Column(db.Integer, db.Sequence("seq_street_segment_id"),primary_key=True)
    yt_id = db.Column(db.String(64), unique = True, index=True, nullable=False)
    name = db.Column(db.String(64), nullable=False)

    def __repr__(self):
        return '<Title {}>'.format(self.name)