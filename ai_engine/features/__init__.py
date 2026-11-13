"""Feature pipeline combining AST vectors with registry metadata."""

from ai_engine.features.pipeline import (
    METADATA_FEATURES,
    FeaturePipeline,
    FeatureSchemaError,
    build_frame,
    metadata_features,
)

__all__ = ["METADATA_FEATURES", "FeaturePipeline", "FeatureSchemaError", "build_frame", "metadata_features"]
