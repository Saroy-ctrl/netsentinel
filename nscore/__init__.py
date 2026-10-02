"""NetSentinel core library - code shared by the offline (ml/) and online (api/) pipelines.

Anything that must behave identically at train time and serve time lives here
(feature transform, fusion, drift math, bundle loading). That is how we avoid
train/serve skew.
"""
