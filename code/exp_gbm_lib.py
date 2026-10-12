import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from kev_lib import Feat
class FeatSmall(Feat):
    """Same features as the logistic model but with a 5,000-term text vocabulary to keep boosting fast."""
    def fit(self, d):
        super().fit(d)
        if self.text: self.tf = TfidfVectorizer(ngram_range=(1, 2), min_df=5, max_features=5000, sublinear_tf=True, stop_words='english').fit((d.title.fillna('') + ' . ' + d.desc.fillna('')))
        return self
PARAMS = dict(n_estimators=300, learning_rate=0.05, num_leaves=15, min_child_samples=20, colsample_bytree=0.2, subsample=0.8, subsample_freq=1, reg_lambda=5.0, scale_pos_weight=10, n_jobs=2, verbose=-1)
