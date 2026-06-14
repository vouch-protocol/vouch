"""vouch-mlflow: sign MLflow model artifacts with Vouch Credentials.

Thin distribution wrapping vouch.integrations.mlflow. It exists so the MLflow
signing helpers can be installed and listed on their own while the
implementation stays single-sourced in the vouch-protocol package.
"""

from vouch.integrations.mlflow import compute_model_digest, sign_model, verify_model

__all__ = ["sign_model", "verify_model", "compute_model_digest"]
__version__ = "0.1.0"
